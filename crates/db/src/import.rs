//! Target side (root): verify a dump, back up what is there, replace the database, check the result.
//!
//! Order matters: nothing that changes the server happens before every check on the file
//! has passed, and nothing is dropped unless the backup of the old database succeeded.

use crate::dump::{check_db_name, choose_mode};
use crate::{dumpfile, Sql};
use flate2::{read::GzDecoder, write::GzEncoder, Compression};
use std::fs::{File, OpenOptions};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

#[derive(Debug)]
pub struct ImportError {
    pub message: String,
    /// False means the server and the backup directory are exactly as before.
    pub changed: bool,
}

impl std::fmt::Display for ImportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}{}", self.message, if self.changed { " (the database may be in a partial state)" } else { "" })
    }
}
impl std::error::Error for ImportError {}

fn refused(m: impl Into<String>) -> ImportError {
    ImportError { message: m.into(), changed: false }
}

pub struct ImportOpts<'a> {
    pub backup_dir: &'a Path,
    pub dry_run: bool,
    pub now: u64,
}

#[derive(Debug, Default)]
pub struct ImportReport {
    pub domain: String,
    pub db: String,
    pub dumped_at: Option<String>,
    pub existed: bool,
    pub tables_before: u64,
    pub tables_in_dump: usize,
    pub backup: Option<PathBuf>,
    pub tables_after: Option<u64>,
    /// DEFINER accounts used by views/triggers/routines that do not exist on this server.
    pub missing_definers: Vec<String>,
    pub warnings: Vec<String>,
    pub imported: bool,
}

fn count(sql: &dyn Sql, q: &str) -> Result<u64, String> {
    let out = sql.query(q)?;
    out.trim().parse().map_err(|_| format!("unexpected count '{}'", out.trim()))
}

fn backup_file(dir: &Path, db: &str, now: u64) -> Result<(PathBuf, GzEncoder<File>), String> {
    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.subsec_nanos()).unwrap_or(0);
    for i in 0..100u32 {
        let name = format!("{db}-{}-{:04x}.sql.gz", crate::stamp(now), (nanos.wrapping_add(i * 7919) ^ std::process::id()) & 0xffff);
        let p = dir.join(name);
        match OpenOptions::new().write(true).create_new(true).mode(0o600).open(&p) {
            Ok(f) => return Ok((p, GzEncoder::new(f, Compression::default()))),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(format!("{}: {e}", p.display())),
        }
    }
    Err("could not pick a free backup file name".into())
}

/// Replace one database from a dump file. See the module comment for the guarantees.
pub fn import(sql: &dyn Sql, file: &Path, opts: &ImportOpts) -> Result<ImportReport, ImportError> {
    // 1. checksum (hash only), then the header and the dump's own USE line
    dumpfile::verify_checksum(file).map_err(|e| refused(format!("{}: {e}", file.display())))?;
    let info = dumpfile::inspect(file).map_err(refused)?;
    let Some(header) = info.header else {
        return Err(refused(format!("{}: not a larry dump (missing header line)", file.display())));
    };
    if info.use_db.as_deref() != Some(header.db.as_str()) {
        return Err(refused(format!(
            "{}: header says db '{}' but the dump switches to '{}'",
            header.domain,
            header.db,
            info.use_db.as_deref().unwrap_or("<none>")
        )));
    }
    check_db_name(&header.db).map_err(refused)?;
    let db = header.db.as_str();

    let mut report = ImportReport {
        domain: header.domain.clone(),
        db: db.into(),
        dumped_at: header.dumped_at.clone(),
        tables_in_dump: info.create_tables,
        ..Default::default()
    };

    // 2. what is on the server now
    let q = |m: &str| refused(format!("{}: {m}", header.domain));
    report.existed = count(sql, &format!("SELECT COUNT(*) FROM information_schema.SCHEMATA WHERE SCHEMA_NAME='{db}'")).map_err(|e| q(&e))? > 0;
    report.tables_before =
        count(sql, &format!("SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA='{db}' AND TABLE_TYPE='BASE TABLE'")).map_err(|e| q(&e))?;
    if opts.dry_run {
        return Ok(report);
    }

    // 3. back up what is there; if that fails, nothing is changed
    if report.existed && report.tables_before > 0 {
        larry_transport::ensure_private_dir(opts.backup_dir).map_err(refused)?;
        let mode = choose_mode(sql, db).map_err(|e| q(&e))?;
        let (path, mut enc) = backup_file(opts.backup_dir, db, opts.now).map_err(refused)?;
        let done = sql.dump(db, mode, &mut enc).and_then(|_| enc.finish().and_then(|f| f.sync_all()).map_err(|e| e.to_string()));
        if let Err(e) = done {
            let _ = std::fs::remove_file(&path);
            return Err(refused(format!("{}: backup of '{db}' failed, nothing changed: {e}", header.domain)));
        }
        report.backup = Some(path);
    }

    // 4. replace. Database-level grants (the app's DB user) survive DROP/CREATE.
    let fail = |m: String| ImportError { message: format!("{}: {m}", header.domain), changed: true };
    sql.query(&format!("DROP DATABASE IF EXISTS `{db}`")).map_err(&fail)?;
    let f = File::open(file).map_err(|e| fail(e.to_string()))?;
    sql.load(&mut GzDecoder::new(f)).map_err(&fail)?;

    let now = count(sql, &format!("SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA='{db}' AND TABLE_TYPE='BASE TABLE'")).map_err(&fail)?;
    report.tables_after = Some(now);
    if now != info.create_tables as u64 {
        report.warnings.push(format!("'{db}' has {now} tables after import, the dump has {} CREATE TABLE statements", info.create_tables));
    }

    // 5. DEFINER accounts: views, triggers and routines run as them, so a missing one
    //    fails at query time, not at import time.
    for (u, h) in &info.definers {
        let plain_u = re!(r"^[A-Za-z0-9_.-]+$").is_match(u);
        let plain_h = re!(r"^[A-Za-z0-9_.%:-]+$").is_match(h);
        if !(plain_u && plain_h) {
            report.warnings.push(format!("unusual definer '{u}'@'{h}': check it by hand"));
            continue;
        }
        let n = count(sql, &format!("SELECT COUNT(*) FROM mysql.user WHERE User='{u}' AND Host='{h}'")).map_err(&fail)?;
        if n == 0 {
            report.missing_definers.push(format!("'{u}'@'{h}'"));
        }
    }
    report.imported = true;
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::*;
    use crate::DumpMode;

    fn dump_text(db: &str, use_db: &str) -> String {
        format!(
            "{}\nCREATE DATABASE `{db}`;\nUSE `{use_db}`;\nCREATE TABLE `a` (id int);\nCREATE TABLE `b` (id int);\n/*!50013 DEFINER=`ghost`@`localhost` SQL SECURITY DEFINER */\n",
            crate::dumpfile::header_line("shop.example.org", db, "src", "2026-11-19T10:00:00Z")
        )
    }

    fn setup(n: &str, text: &str) -> (PathBuf, PathBuf) {
        let d = tmp(n);
        let p = gz(&d, "shop.example.org.db.sql.gz", text);
        crate::dumpfile::write_sidecar(&p).unwrap();
        (d, p)
    }

    #[test]
    fn happy_path_backs_up_then_replaces_in_order() {
        let (d, p) = setup("ok", &dump_text("shop_db", "shop_db"));
        let sql = FakeSql::new(true, 5);
        let r = import(&sql, &p, &ImportOpts { backup_dir: &d.join("bak"), dry_run: false, now: 1_700_000_000 }).unwrap();
        assert!(r.imported && r.existed);
        assert_eq!((r.tables_before, r.tables_in_dump, r.tables_after), (5, 2, Some(2)));
        assert_eq!(r.missing_definers, ["'ghost'@'localhost'"]);
        assert!(r.warnings.is_empty());
        let bak = r.backup.unwrap();
        assert!(bak.to_string_lossy().contains("shop_db-20231114-221320-"));
        let log = sql.log();
        let pos = |needle: &str| log.iter().position(|l| l.contains(needle)).unwrap_or_else(|| panic!("{needle} not in {log:?}"));
        assert!(pos("dump shop_db") < pos("DROP DATABASE") && pos("DROP DATABASE") < pos("load"));
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn new_database_needs_no_backup() {
        let (d, p) = setup("new", &dump_text("shop_db", "shop_db"));
        let sql = FakeSql::new(false, 0);
        let r = import(&sql, &p, &ImportOpts { backup_dir: &d.join("bak"), dry_run: false, now: 0 }).unwrap();
        assert!(r.backup.is_none() && r.imported);
        assert!(!sql.log().iter().any(|l| l.starts_with("dump")));
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn dry_run_changes_nothing() {
        let (d, p) = setup("dry", &dump_text("shop_db", "shop_db"));
        let sql = FakeSql::new(true, 5);
        let r = import(&sql, &p, &ImportOpts { backup_dir: &d.join("bak"), dry_run: true, now: 0 }).unwrap();
        assert!(!r.imported && r.backup.is_none());
        assert!(sql.log().iter().all(|l| l.starts_with("query") && !l.contains("DROP")));
        assert!(!d.join("bak").exists());
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn failed_backup_aborts_before_drop() {
        let (d, p) = setup("badbak", &dump_text("shop_db", "shop_db"));
        let mut sql = FakeSql::new(true, 5);
        sql.fail_dump = true;
        let e = import(&sql, &p, &ImportOpts { backup_dir: &d.join("bak"), dry_run: false, now: 0 }).unwrap_err();
        assert!(!e.changed && e.message.contains("backup"));
        assert!(!sql.log().iter().any(|l| l.contains("DROP") || l.starts_with("load")));
        assert_eq!(std::fs::read_dir(d.join("bak")).unwrap().count(), 0, "partial backup removed");
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn tampered_or_mismatched_dumps_change_nothing() {
        let sql_untouched = |sql: &FakeSql| assert!(sql.log().is_empty(), "server was contacted: {:?}", sql.log());
        let opts = |d: &Path| ImportOpts { backup_dir: Box::leak(Box::new(d.join("bak"))), dry_run: false, now: 0 };

        // bad checksum
        let (d, p) = setup("t1", &dump_text("shop_db", "shop_db"));
        let mut b = std::fs::read(&p).unwrap();
        let n = b.len();
        b[n - 3] ^= 0xff;
        std::fs::write(&p, b).unwrap();
        let sql = FakeSql::new(true, 5);
        assert!(!import(&sql, &p, &opts(&d)).unwrap_err().changed);
        sql_untouched(&sql);

        // no sidecar
        let (d2, p2) = setup("t2", &dump_text("shop_db", "shop_db"));
        std::fs::remove_file(crate::dumpfile::sidecar(&p2)).unwrap();
        let sql = FakeSql::new(true, 5);
        assert!(import(&sql, &p2, &opts(&d2)).is_err());
        sql_untouched(&sql);

        // missing header
        let (d3, p3) = setup("t3", "-- plain mysqldump\nUSE `shop_db`;\n");
        let sql = FakeSql::new(true, 5);
        assert!(import(&sql, &p3, &opts(&d3)).unwrap_err().message.contains("missing header"));
        sql_untouched(&sql);

        // header names one database, the dump switches to another
        let (d4, p4) = setup("t4", &dump_text("shop_db", "other_db"));
        let sql = FakeSql::new(true, 5);
        assert!(import(&sql, &p4, &opts(&d4)).unwrap_err().message.contains("switches to 'other_db'"));
        sql_untouched(&sql);

        // system database
        let (d5, p5) = setup("t5", &dump_text("mysql", "mysql"));
        let sql = FakeSql::new(true, 5);
        assert!(import(&sql, &p5, &opts(&d5)).unwrap_err().message.contains("system database"));
        sql_untouched(&sql);
        for d in [d, d2, d3, d4, d5] {
            std::fs::remove_dir_all(d).unwrap();
        }
    }

    #[test]
    fn dump_modes() {
        let sql = FakeSql::new(true, 1);
        sql.set_nontx(0);
        assert_eq!(choose_mode(&sql, "a").unwrap(), DumpMode::SingleTransaction);
        sql.set_nontx(2);
        assert_eq!(choose_mode(&sql, "a").unwrap(), DumpMode::LockTables);
        assert!(choose_mode(&sql, "a; DROP").is_err());
    }
}
