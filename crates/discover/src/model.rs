//! Inventory records: one JSON line per source vhost in `inventory.jsonl`.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Level {
    /// Context only; does not change the exit status.
    Info,
    /// A human has to decide or check something; exit status 2.
    Review,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Finding {
    pub level: Level,
    pub code: String,
    pub message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DbStatus {
    /// Exactly one existing database found.
    Resolved,
    /// No reference found (static site, presumably).
    #[serde(rename = "none")]
    Absent,
    /// Several candidates, or a name that does not exist here. Held back, never guessed.
    Unresolved,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DbInfo {
    pub status: DbStatus,
    pub name: Option<String>,
    /// `relative/path:line` of the reference that named the database.
    pub source: Option<String>,
    /// False when `--no-db-check` skipped `SHOW DATABASES`.
    pub verified: bool,
    pub note: String,
    /// Every name found with its references (for unresolved sites).
    #[serde(default)]
    pub candidates: BTreeMap<String, Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PhpSetting {
    /// `php_value`, `php_flag`, `php_admin_value` or `php_admin_flag`.
    pub kind: String,
    pub name: String,
    pub value: String,
    pub source: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PathHit {
    pub file: String,
    pub count: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Record {
    pub domain: String,
    pub aliases: Vec<String>,
    pub conf_files: Vec<String>,
    pub docroots: Vec<String>,
    pub docroot: Option<String>,
    pub docroot_exists: bool,
    pub docroot_name: Option<String>,
    pub vhost_root: Option<String>,
    pub ssl: bool,
    /// `fpm`, `mod_php`, `static` or `unknown`.
    pub php_mode: String,
    pub fpm_socket: Option<String>,
    /// Why this vhost gets no files (redirect-only, default vhost, missing docroot, ...).
    pub skip: Option<String>,
    pub nested_in: Option<String>,
    /// Absolute paths of nested vhost trees; this site's copy excludes them.
    #[serde(default)]
    pub exclude_paths: Vec<String>,
    pub db: DbInfo,
    #[serde(default)]
    pub php_settings: Vec<PhpSetting>,
    pub size_bytes: u64,
    pub file_count: u64,
    #[serde(default)]
    pub old_path_hits: Vec<PathHit>,
    #[serde(default)]
    pub findings: Vec<Finding>,
}

impl Record {
    pub fn new(domain: &str) -> Self {
        Record {
            domain: domain.into(),
            aliases: vec![],
            conf_files: vec![],
            docroots: vec![],
            docroot: None,
            docroot_exists: false,
            docroot_name: None,
            vhost_root: None,
            ssl: false,
            php_mode: "unknown".into(),
            fpm_socket: None,
            skip: None,
            nested_in: None,
            exclude_paths: vec![],
            db: DbInfo { status: DbStatus::Absent, name: None, source: None, verified: true, note: String::new(), candidates: BTreeMap::new() },
            php_settings: vec![],
            size_bytes: 0,
            file_count: 0,
            old_path_hits: vec![],
            findings: vec![],
        }
    }

    pub fn add(&mut self, level: Level, code: &str, message: impl Into<String>) {
        self.findings.push(Finding { level, code: code.into(), message: message.into() });
    }

    pub fn needs_review(&self) -> bool {
        self.findings.iter().any(|f| f.level == Level::Review)
    }
}
