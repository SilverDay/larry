//! larry-db: database dump (source), verified import (target) and database checks.
//!
//! One path for the first copy and every re-sync: dump on the source, verify,
//! then back up and replace on the target (see docs/spec.md, Database handling).
//! Credentials only come from MySQL defaults files; SQL (which may contain an app
//! password) is always sent on stdin, never on a command line.

macro_rules! re {
    ($p:expr) => {{
        static R: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
        R.get_or_init(|| regex::Regex::new($p).expect("static regex compiles"))
    }};
}

pub mod checks;
pub mod dump;
pub mod dumpfile;
pub mod import;
#[cfg(test)]
mod testutil;

use larry_transport::Cmd;
use std::io::{Read, Write};
use std::path::PathBuf;

pub const SYSTEM_DBS: [&str; 4] = ["mysql", "sys", "information_schema", "performance_schema"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DumpMode {
    /// All InnoDB: a consistent snapshot without blocking writers.
    SingleTransaction,
    /// Any non-InnoDB table: MariaDB ignores `--lock-tables` when combined with
    /// `--single-transaction`, so exactly one of the two is ever passed.
    LockTables,
}

impl DumpMode {
    pub fn flag(self) -> &'static str {
        match self {
            DumpMode::SingleTransaction => "--single-transaction",
            DumpMode::LockTables => "--lock-tables",
        }
    }
}

/// What the tool needs from a database server. The real implementation shells out to the
/// system `mysql`/`mysqldump`; tests use a fake.
pub trait Sql {
    /// Run SQL (sent on stdin) and return its tab-separated rows without headers.
    fn query(&self, sql: &str) -> Result<String, String>;
    /// Stream a dump of one database (with routines, triggers and events) into `out`.
    fn dump(&self, db: &str, mode: DumpMode, out: &mut (dyn Write + Send)) -> Result<(), String>;
    /// Feed SQL from `input` to the server (an import).
    fn load(&self, input: &mut (dyn Read + Send)) -> Result<(), String>;
}

pub struct MysqlCli {
    pub defaults_file: PathBuf,
    dump_tool: String,
}

impl MysqlCli {
    pub fn new(defaults_file: PathBuf) -> Result<Self, String> {
        let dump_tool = larry_transport::find_tool(&["mysqldump", "mariadb-dump"]).ok_or("neither mysqldump nor mariadb-dump found in PATH")?;
        Ok(MysqlCli { defaults_file, dump_tool })
    }

    fn base(&self, tool: &str) -> Cmd {
        // --defaults-extra-file must be the first option.
        Cmd::new(tool).arg(format!("--defaults-extra-file={}", self.defaults_file.display()))
    }
}

fn explain(what: &str, out: &larry_transport::Output) -> String {
    format!("{what} failed (status {}): {}", out.code.map(|c| c.to_string()).unwrap_or("signal".into()), out.stderr.trim())
}

impl Sql for MysqlCli {
    fn query(&self, sql: &str) -> Result<String, String> {
        let out = self.base("mysql").args(["-N", "-B"]).stdin_data(sql).run().map_err(|e| e.to_string())?;
        if out.success() {
            Ok(out.stdout)
        } else {
            Err(explain("mysql", &out))
        }
    }

    fn dump(&self, db: &str, mode: DumpMode, out: &mut (dyn Write + Send)) -> Result<(), String> {
        let r = self
            .base(&self.dump_tool)
            .arg(mode.flag())
            .args(["--routines", "--triggers", "--events", "--databases", db])
            .stream(None, Some(out))
            .map_err(|e| e.to_string())?;
        if r.success() {
            Ok(())
        } else {
            Err(explain(&self.dump_tool, &r))
        }
    }

    fn load(&self, input: &mut (dyn Read + Send)) -> Result<(), String> {
        let r = self.base("mysql").stream(Some(input), None).map_err(|e| e.to_string())?;
        if r.success() {
            Ok(())
        } else {
            Err(explain("mysql (import)", &r))
        }
    }
}

// ---------------------------------------------------------------- time (no chrono needed)

fn civil(secs: u64) -> (i64, u32, u32, u64, u64, u64) {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = yoe + era * 400 + if m <= 2 { 1 } else { 0 };
    (y, m, d, rem / 3600, rem % 3600 / 60, rem % 60)
}

/// `2026-11-19T12:00:00Z`
pub fn utc_iso(secs: u64) -> String {
    let (y, m, d, hh, mm, ss) = civil(secs);
    format!("{y:04}-{m:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}Z")
}

/// `20261119-120000`, for backup file names.
pub fn stamp(secs: u64) -> String {
    let (y, m, d, hh, mm, ss) = civil(secs);
    format!("{y:04}{m:02}{d:02}-{hh:02}{mm:02}{ss:02}")
}

pub fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn time_formatting() {
        assert_eq!(utc_iso(0), "1970-01-01T00:00:00Z");
        assert_eq!(utc_iso(1_700_000_000), "2023-11-14T22:13:20Z");
        assert_eq!(utc_iso(1_709_164_800), "2024-02-29T00:00:00Z");
        assert_eq!(stamp(1_700_000_000), "20231114-221320");
    }
}
