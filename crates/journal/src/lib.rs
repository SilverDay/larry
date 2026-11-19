//! larry-journal: `state/journal.jsonl`, one JSON line per changing step.
//!
//! Entries hold site, target, step, plan hash, checksums and result. Secrets
//! never go in: callers only pass checksums and short messages.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug)]
pub enum Error {
    Io(String, std::io::Error),
    Corrupt { path: String, line: usize, msg: String },
    PlanChanged { journal: String, current: String },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(p, e) => write!(f, "{p}: {e}"),
            Error::Corrupt { path, line, msg } => write!(f, "{path}:{line}: {msg}"),
            Error::PlanChanged { journal, current } => write!(
                f,
                "the plan changed since the journal was written (journal {journal}, now {current}); refusing to resume"
            ),
        }
    }
}
impl std::error::Error for Error {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Outcome {
    Ok,
    Failed,
    Skipped,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Entry {
    pub ts: u64,
    pub site: String,
    pub target: String,
    pub step: String,
    pub plan_hash: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub checksums: BTreeMap<String, String>,
    pub result: Outcome,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

impl Entry {
    pub fn new(site: &str, target: &str, step: &str, plan_hash: &str, result: Outcome) -> Self {
        Entry {
            ts: SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0),
            site: site.into(),
            target: target.into(),
            step: step.into(),
            plan_hash: plan_hash.into(),
            checksums: BTreeMap::new(),
            result,
            message: None,
        }
    }
}

/// Hex sha256 of the plan's bytes (the reviewed `sites.toml`).
pub fn plan_hash(bytes: &[u8]) -> String {
    Sha256::digest(bytes).iter().map(|b| format!("{b:02x}")).collect()
}

pub struct Journal {
    path: PathBuf,
    file: File,
    entries: Vec<Entry>,
}

impl Journal {
    /// Open (creating mode 0600 if needed) and load the existing entries.
    /// A corrupt line is an error: a journal that cannot be trusted must not drive a resume.
    pub fn open(path: &Path) -> Result<Self, Error> {
        let p = path.display().to_string();
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).map_err(|e| Error::Io(p.clone(), e))?;
        }
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(path)
            .map_err(|e| Error::Io(p.clone(), e))?;
        let mut entries = Vec::new();
        let reader = BufReader::new(File::open(path).map_err(|e| Error::Io(p.clone(), e))?);
        for (i, line) in reader.lines().enumerate() {
            let line = line.map_err(|e| Error::Io(p.clone(), e))?;
            let line = line.trim_end_matches('\r');
            if line.trim().is_empty() {
                continue;
            }
            let entry = serde_json::from_str(line)
                .map_err(|e| Error::Corrupt { path: p.clone(), line: i + 1, msg: e.to_string() })?;
            entries.push(entry);
        }
        Ok(Journal { path: path.to_path_buf(), file, entries })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    /// Append one line and flush it to disk before returning.
    pub fn append(&mut self, entry: Entry) -> Result<(), Error> {
        let p = self.path.display().to_string();
        let mut line = serde_json::to_string(&entry).expect("entry serializes");
        line.push('\n');
        self.file.write_all(line.as_bytes()).map_err(|e| Error::Io(p.clone(), e))?;
        self.file.sync_data().map_err(|e| Error::Io(p, e))?;
        self.entries.push(entry);
        Ok(())
    }

    /// `--resume` precondition: the journal's latest plan hash must equal the current one.
    pub fn check_resume(&self, current_plan_hash: &str) -> Result<(), Error> {
        match self.entries.last() {
            Some(last) if last.plan_hash != current_plan_hash => Err(Error::PlanChanged {
                journal: last.plan_hash.clone(),
                current: current_plan_hash.into(),
            }),
            _ => Ok(()),
        }
    }

    /// True when the latest record for this site/target/step under this plan hash succeeded.
    pub fn is_done(&self, site: &str, target: &str, step: &str, plan_hash: &str) -> bool {
        self.entries
            .iter()
            .rev()
            .find(|e| e.site == site && e.target == target && e.step == step && e.plan_hash == plan_hash)
            .map(|e| e.result == Outcome::Ok)
            .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("larry-journal-{}-{}", name, std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    #[test]
    fn append_reload_resume() {
        let dir = tmp("a");
        let path = dir.join("state/journal.jsonl");
        let h = plan_hash(b"plan one");
        {
            let mut j = Journal::open(&path).unwrap();
            let mut e = Entry::new("a.de", "web1", "files", &h, Outcome::Ok);
            e.checksums.insert("pkg".into(), "abc".into());
            j.append(e).unwrap();
            j.append(Entry::new("b.de", "web1", "files", &h, Outcome::Failed)).unwrap();
        }
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        let j = Journal::open(&path).unwrap();
        assert_eq!(j.entries().len(), 2);
        assert!(j.is_done("a.de", "web1", "files", &h));
        assert!(!j.is_done("b.de", "web1", "files", &h));
        assert!(!j.is_done("a.de", "web1", "files", &plan_hash(b"other")));
        assert!(j.check_resume(&h).is_ok());
        assert!(matches!(j.check_resume(&plan_hash(b"plan two")), Err(Error::PlanChanged { .. })));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn later_failure_overrides_earlier_ok() {
        let dir = tmp("b");
        let mut j = Journal::open(&dir.join("j.jsonl")).unwrap();
        j.append(Entry::new("a.de", "t", "db", "h", Outcome::Ok)).unwrap();
        j.append(Entry::new("a.de", "t", "db", "h", Outcome::Failed)).unwrap();
        assert!(!j.is_done("a.de", "t", "db", "h"));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn corrupt_line_is_refused_and_crlf_tolerated() {
        let dir = tmp("c");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("j.jsonl");
        std::fs::write(&path, "not json\n").unwrap();
        assert!(matches!(Journal::open(&path), Err(Error::Corrupt { line: 1, .. })));
        let line = serde_json::to_string(&Entry::new("a.de", "t", "s", "h", Outcome::Ok)).unwrap();
        std::fs::write(&path, format!("{line}\r\n")).unwrap();
        assert_eq!(Journal::open(&path).unwrap().entries().len(), 1);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
