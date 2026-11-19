//! Database-name detection (ported from build-migration-manifest.py).
//!
//! Only database NAMES are ever extracted: credentials are never captured or printed.

use crate::model::{DbInfo, DbStatus};
use regex::Regex;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

pub const SYSTEM_DBS: [&str; 4] = ["mysql", "information_schema", "performance_schema", "sys"];

const CONFIG_NAMES: [&str; 17] = [
    "wp-config.php", ".env", ".env.local", ".env.production", ".env.prod",
    "configuration.php",      // Joomla
    "config.ini.php",         // Matomo
    "settings.php",           // Drupal, TYPO3 v12+
    "localconfiguration.php", // TYPO3 <= 11
    "env.php",                // Magento
    "parameters.yml", "parameters.yaml", "database.yml", "database.yaml",
    "config.php", "config.inc", "config.inc.php",
];
const PRUNE_DIRS: [&str; 10] =
    ["vendor", "node_modules", ".git", ".svn", ".hg", "cache", "tmp", "temp", "logs", "log"];
const PRUNE_DIRS_MORE: [&str; 3] = ["uploads", "backup", "backups"];
const MAX_FILE_BYTES: u64 = 1_000_000;

const N: &str = r"([A-Za-z0-9_\-]+)";

fn db_patterns() -> &'static [Regex] {
    static P: OnceLock<Vec<Regex>> = OnceLock::new();
    P.get_or_init(|| {
        let src = [
            // define('DB_NAME', 'x') -- WordPress and many custom apps
            format!(r#"define\s*\(\s*['"](?:DB_NAME|DB_DATABASE|DATABASE_NAME)['"]\s*,\s*['"]{N}['"]"#),
            // .env style
            format!(r#"^\s*(?:export\s+)?(?:DB_DATABASE|DB_NAME|MYSQL_DATABASE|DATABASE_NAME)\s*=\s*['"]?{N}"#),
            // PDO DSN: mysql:host=...;dbname=x
            format!(r#"(?:mysql|mariadb):[^'"\s]*?dbname={N}"#),
            // URL: mysql://user:pass@host:3306/x
            format!(r#"(?:mysql|mariadb)://[^/\s'"]+/{N}"#),
            // arrays: 'dbname' => 'x'
            format!(r#"['"](?:dbname|database|db_name|dbName|db_database)['"]\s*=>\s*['"]{N}['"]"#),
            // Matomo / ini: dbname = "x"
            format!(r#"^\s*(?:dbname|database)\s*=\s*['"]?{N}"#),
            // Joomla: public $db = 'x';
            format!(r#"(?:public|var)\s+\$db\s*=\s*['"]{N}['"]"#),
            // plain PHP variables
            format!(r#"\$(?:db_?name|database|db_database|dbName)\s*=\s*['"]{N}['"]"#),
            // mysqli_connect('host','user','pass','x') / new mysqli(...)
            format!(
                r#"(?:mysqli_connect|new\s+mysqli)\s*\(\s*['"][^'"]*['"]\s*,\s*['"][^'"]*['"]\s*,\s*['"][^'"]*['"]\s*,\s*['"]{N}['"]"#
            ),
            // mysqli_select_db($link, 'x')
            format!(r#"mysqli?_select_db\s*\(\s*(?:\$\w+\s*,\s*)?['"]{N}['"]"#),
            // YAML: database_name: x
            format!(r#"^\s*database(?:_name)?\s*:\s*['"]?{N}"#),
        ];
        src.iter().map(|p| Regex::new(p).expect("detector compiles")).collect()
    })
}

fn is_config_file(name: &str) -> bool {
    if re!(r"(?i)(sample|example|\.dist$|\.bak$|\.orig$|~$)").is_match(name) {
        return false;
    }
    let low = name.to_ascii_lowercase();
    if CONFIG_NAMES.contains(&low.as_str()) {
        return true;
    }
    re!(r"(?i)^(config.*\.(php|inc|ini)|.*config\.(php|inc)|db.*\.(php|inc)|database.*\.(php|inc)|connect.*\.(php|inc)|settings.*\.(php|inc)|.*\.ini\.php)$")
        .is_match(name)
}

/// Names found on one line of a config file (comment lines are skipped).
pub fn names_in_line(line: &str) -> Vec<String> {
    if re!(r"^\s*(//|#|;|\*|/\*)").is_match(line) {
        return vec![];
    }
    let mut out = vec![];
    for p in db_patterns() {
        for c in p.captures_iter(line) {
            out.push(c[1].to_string());
        }
    }
    out
}

/// `{dbname: ["relpath:line", ...]}` found below `search_root`.
/// Never follows symlinks: a link in a web tree must not make us read files outside it.
pub fn find_candidates(search_root: &Path, prune: &BTreeSet<PathBuf>, max_depth: usize) -> BTreeMap<String, Vec<String>> {
    let mut found: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut stack = vec![(search_root.to_path_buf(), 0usize)];
    while let Some((dir, depth)) = stack.pop() {
        let Ok(rd) = fs::read_dir(&dir) else { continue };
        let mut entries: Vec<_> = rd.flatten().collect();
        entries.sort_by_key(|e| e.file_name());
        for e in entries {
            let Ok(ft) = e.file_type() else { continue };
            let path = e.path();
            let name = e.file_name().to_string_lossy().into_owned();
            if ft.is_symlink() {
                continue;
            }
            if ft.is_dir() {
                let low = name.to_ascii_lowercase();
                let pruned = PRUNE_DIRS.contains(&low.as_str())
                    || PRUNE_DIRS_MORE.contains(&low.as_str())
                    || prune.contains(&path)
                    || (depth == 0 && name == "subdomains"); // Plesk: other vhosts live here
                if !pruned && depth < max_depth {
                    stack.push((path, depth + 1));
                }
            } else if ft.is_file() && is_config_file(&name) {
                if e.metadata().map(|m| m.len() > MAX_FILE_BYTES).unwrap_or(true) {
                    continue;
                }
                let Ok(bytes) = fs::read(&path) else { continue };
                let text = String::from_utf8_lossy(&bytes);
                let rel = path.strip_prefix(search_root).unwrap_or(&path).display().to_string();
                for (i, line) in text.lines().enumerate() {
                    for n in names_in_line(line) {
                        found.entry(n).or_default().push(format!("{rel}:{}", i + 1));
                    }
                }
            }
        }
    }
    found
}

fn list(m: &BTreeMap<String, Vec<String>>) -> String {
    m.iter().map(|(k, v)| format!("{k} ({})", v[0])).collect::<Vec<_>>().join("; ")
}

/// Decide the database. A name only counts if it exists on the server; ambiguity is never guessed.
pub fn resolve(found: &BTreeMap<String, Vec<String>>, dbs: Option<&BTreeSet<String>>) -> DbInfo {
    let mk = |status, name: Option<&String>, source: Option<String>, verified, note: String, cands: &BTreeMap<String, Vec<String>>| DbInfo {
        status,
        name: name.cloned(),
        source,
        verified,
        note,
        candidates: cands.clone(),
    };
    let empty = BTreeMap::new();
    match dbs {
        None => match found.len() {
            0 => mk(DbStatus::Absent, None, None, true, "no DB reference found (static site?)".into(), &empty),
            1 => {
                let (n, v) = found.iter().next().unwrap();
                mk(DbStatus::Resolved, Some(n), Some(v[0].clone()), false, format!("UNVERIFIED (--no-db-check) from {}", v[0]), &empty)
            }
            _ => mk(DbStatus::Unresolved, None, None, false, format!("several DB names found: {}", list(found)), found),
        },
        Some(dbs) => {
            let verified: BTreeMap<_, _> = found.iter().filter(|(k, _)| dbs.contains(*k)).map(|(k, v)| (k.clone(), v.clone())).collect();
            match verified.len() {
                1 => {
                    let (n, v) = verified.iter().next().unwrap();
                    mk(DbStatus::Resolved, Some(n), Some(v[0].clone()), true, format!("from {}", v[0]), &empty)
                }
                0 if found.is_empty() => mk(DbStatus::Absent, None, None, true, "no DB reference found (static site?)".into(), &empty),
                0 => mk(
                    DbStatus::Unresolved, None, None, true,
                    format!("DB name(s) found but no such database here: {} (remote DB? stale config?)", list(found)),
                    found,
                ),
                _ => mk(
                    DbStatus::Unresolved, None, None, true,
                    format!("ambiguous, several existing databases referenced: {}", list(&verified)),
                    &verified,
                ),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn one(line: &str) -> Vec<String> {
        names_in_line(line)
    }

    #[test]
    fn detectors() {
        assert_eq!(one("define( 'DB_NAME', 'wp_blog' );"), ["wp_blog"]);
        assert_eq!(one("DB_DATABASE=laravel_db"), ["laravel_db"]);
        assert_eq!(one("export MYSQL_DATABASE=\"x-y\""), ["x-y"]);
        assert_eq!(one("$pdo = new PDO('mysql:host=localhost;dbname=shop;charset=utf8', $u, $p);"), ["shop"]);
        assert_eq!(one("DATABASE_URL=mysql://u:p@127.0.0.1:3306/appdb"), ["appdb"]);
        assert_eq!(one("'dbname' => 'cms',"), ["cms"]);
        assert_eq!(one("dbname = \"matomo\""), ["matomo"]);
        assert_eq!(one("public $db = 'joomla';"), ["joomla"]);
        assert_eq!(one("$dbname = \"legacy\";"), ["legacy"]);
        assert_eq!(one("$c = mysqli_connect('localhost','u','p','oldapp');"), ["oldapp"]);
        assert_eq!(one("mysqli_select_db($link, 'sel');"), ["sel"]);
        assert_eq!(one("  database_name: sym"), ["sym"]);
    }

    #[test]
    fn comments_are_ignored_and_credentials_never_captured() {
        assert!(one("// define('DB_NAME', 'old');").is_empty());
        assert!(one("# DB_DATABASE=old").is_empty());
        assert!(one("define('DB_PASSWORD', 'hunter2');").is_empty());
    }

    #[test]
    fn resolution_never_guesses() {
        let mut found = BTreeMap::new();
        found.insert("a_db".to_string(), vec!["wp-config.php:3".to_string()]);
        let dbs: BTreeSet<String> = ["a_db", "b_db"].iter().map(|s| s.to_string()).collect();
        assert_eq!(resolve(&found, Some(&dbs)).status, DbStatus::Resolved);
        assert!(!resolve(&found, None).verified);

        found.insert("b_db".to_string(), vec![".env:1".to_string()]);
        assert_eq!(resolve(&found, Some(&dbs)).status, DbStatus::Unresolved);

        let mut ghost = BTreeMap::new();
        ghost.insert("gone".to_string(), vec!["x.php:1".to_string()]);
        let r = resolve(&ghost, Some(&dbs));
        assert_eq!(r.status, DbStatus::Unresolved);
        assert!(r.name.is_none());

        assert_eq!(resolve(&BTreeMap::new(), Some(&dbs)).status, DbStatus::Absent);
    }
}
