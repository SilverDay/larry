//! Source side: dump one database into `<staging>/<domain>.db.sql.gz` with header and checksum.

use crate::{dumpfile, DumpMode, Sql, SYSTEM_DBS};
use flate2::{write::GzEncoder, Compression};
use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

#[derive(Debug)]
pub struct DumpResult {
    pub path: PathBuf,
    pub sha256: String,
    pub mode: DumpMode,
    pub bytes: u64,
}

pub fn check_db_name(db: &str) -> Result<(), String> {
    if !larry_config::is_db_name(db) {
        return Err(format!("'{db}' is not a plain database name"));
    }
    if SYSTEM_DBS.contains(&db) {
        return Err(format!("refusing system database '{db}'"));
    }
    Ok(())
}

/// All InnoDB means a snapshot; any other engine means locking the tables, because
/// `--single-transaction` would not give a consistent copy of those.
pub fn choose_mode(sql: &dyn Sql, db: &str) -> Result<DumpMode, String> {
    check_db_name(db)?;
    let out = sql.query(&format!(
        "SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA='{db}' AND TABLE_TYPE='BASE TABLE' AND ENGINE NOT IN ('InnoDB')"
    ))?;
    let n: u64 = out.trim().parse().map_err(|_| format!("unexpected engine count '{}'", out.trim()))?;
    Ok(if n > 0 { DumpMode::LockTables } else { DumpMode::SingleTransaction })
}

/// Dump to `<staging>/<domain>.db.sql.gz`: written as `.part`, renamed when complete, checksummed.
/// The staging directory must already exist (see `larry_transport::ensure_private_dir`).
pub fn dump_database(sql: &dyn Sql, domain: &str, db: &str, source: &str, staging: &Path, now: u64) -> Result<DumpResult, String> {
    if !larry_config::is_domain(domain) {
        return Err(format!("'{domain}' is not a usable domain name"));
    }
    let mode = choose_mode(sql, db)?;
    let out = staging.join(format!("{domain}.db.sql.gz"));
    let part = staging.join(format!("{domain}.db.sql.gz.part"));
    let side = dumpfile::sidecar(&out);
    let _ = std::fs::remove_file(&out);
    let _ = std::fs::remove_file(&side);

    let result = (|| -> Result<(), String> {
        let f = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&part)
            .map_err(|e| format!("{}: {e}", part.display()))?;
        let mut enc = GzEncoder::new(f, Compression::default());
        let header = dumpfile::header_line(domain, db, source, &crate::utc_iso(now));
        writeln!(enc, "{header}").map_err(|e| e.to_string())?;
        sql.dump(db, mode, &mut enc)?;
        let f = enc.finish().map_err(|e| e.to_string())?;
        f.sync_all().map_err(|e| e.to_string())
    })();
    if let Err(e) = result {
        let _ = std::fs::remove_file(&part);
        return Err(format!("dump of '{db}' failed: {e}"));
    }
    std::fs::rename(&part, &out).map_err(|e| format!("{}: {e}", out.display()))?;
    let sha256 = dumpfile::write_sidecar(&out)?;
    let bytes = std::fs::metadata(&out).map(|m| m.len()).unwrap_or(0);
    Ok(DumpResult { path: out, sha256, mode, bytes })
}
