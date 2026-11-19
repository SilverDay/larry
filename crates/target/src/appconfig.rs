//! The application's own database credentials, read from the config it just received, so the first
//! `target apply` can create the matching `'user'@'localhost'`. Supported: WordPress `wp-config.php`,
//! `.env` files (Laravel and friends) and Joomla `configuration.php`. Anything else is reported so
//! the admin creates the user by hand. The password is only ever held in memory.

use regex::Regex;
use std::path::{Path, PathBuf};

#[derive(Clone, PartialEq)]
pub struct Creds {
    pub user: String,
    pub password: String,
    pub host: Option<String>,
    /// Config file the values came from (relative to the search root).
    pub source: String,
}

impl std::fmt::Debug for Creds {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Creds {{ user: {:?}, password: <hidden>, host: {:?}, source: {:?} }}", self.user, self.host, self.source)
    }
}

fn first(re: &Regex, text: &str) -> Option<String> {
    text.lines().filter(|l| !l.trim_start().starts_with(['#', '/', '*'])).find_map(|l| re.captures(l).map(|c| c[1].to_string()))
}

fn define(key: &str, text: &str) -> Option<String> {
    let re = Regex::new(&format!(r#"define\s*\(\s*['"]{key}['"]\s*,\s*(?:'([^']*)'|"([^"]*)")"#)).unwrap();
    text.lines().filter(|l| !l.trim_start().starts_with(['#', '/', '*'])).find_map(|l| {
        re.captures(l).map(|c| c.get(1).or(c.get(2)).map(|m| m.as_str().to_string()).unwrap_or_default())
    })
}

fn env(keys: &[&str], text: &str) -> Option<String> {
    for k in keys {
        let re = Regex::new(&format!(r#"^\s*(?:export\s+)?{k}\s*=\s*(?:'([^']*)'|"([^"]*)"|([^\s#]*))"#)).unwrap();
        for l in text.lines() {
            if let Some(c) = re.captures(l) {
                return c.get(1).or(c.get(2)).or(c.get(3)).map(|m| m.as_str().to_string());
            }
        }
    }
    None
}

fn joomla(var: &str, text: &str) -> Option<String> {
    first(&Regex::new(&format!(r#"public\s+\${var}\s*=\s*'([^']*)'"#)).unwrap(), text)
}

/// Credentials in one file whose database is `db`, if it is a supported config.
pub fn from_file(path: &Path, rel: &str, db: &str) -> Option<Creds> {
    let name = path.file_name()?.to_string_lossy().to_ascii_lowercase();
    let text = std::fs::read_to_string(path).ok().filter(|t| t.len() < 1_000_000)?;
    let (name_v, user, pass, host) = if name == "wp-config.php" {
        (define("DB_NAME", &text), define("DB_USER", &text), define("DB_PASSWORD", &text), define("DB_HOST", &text))
    } else if name == ".env" || name.starts_with(".env.") {
        (
            env(&["DB_DATABASE", "DB_NAME", "MYSQL_DATABASE"], &text),
            env(&["DB_USERNAME", "DB_USER", "MYSQL_USER"], &text),
            env(&["DB_PASSWORD", "MYSQL_PASSWORD"], &text),
            env(&["DB_HOST"], &text),
        )
    } else if name == "configuration.php" {
        (joomla("db", &text), joomla("user", &text), joomla("password", &text), joomla("host", &text))
    } else {
        return None;
    };
    (name_v.as_deref() == Some(db)).then_some(())?;
    Some(Creds { user: user?, password: pass?, host, source: rel.to_string() })
}

/// Search below `root` (depth 3, skipping dependency and cache directories) for credentials of `db`.
pub fn find(root: &Path, db: &str) -> Option<Creds> {
    fn walk(base: &Path, dir: &Path, depth: usize, db: &str) -> Option<Creds> {
        let mut es: Vec<_> = std::fs::read_dir(dir).ok()?.flatten().collect();
        es.sort_by_key(|e| e.file_name());
        for e in &es {
            let t = e.file_type().ok()?;
            let p: PathBuf = e.path();
            if t.is_file() {
                let rel = p.strip_prefix(base).unwrap().display().to_string();
                if let Some(c) = from_file(&p, &rel, db) {
                    return Some(c);
                }
            }
        }
        if depth < 3 {
            for e in &es {
                let n = e.file_name().to_string_lossy().to_string();
                if e.file_type().ok()?.is_dir() && !["vendor", "node_modules", ".git", "cache", "tmp", "logs"].contains(&n.as_str()) {
                    if let Some(c) = walk(base, &e.path(), depth + 1, db) {
                        return Some(c);
                    }
                }
            }
        }
        None
    }
    walk(root, root, 0, db)
}

/// Only `localhost` style hosts match the `'user'@'localhost'` account the tool creates.
pub fn is_local_host(host: &Option<String>) -> bool {
    matches!(host.as_deref().map(str::trim), None | Some("") | Some("localhost") | Some("127.0.0.1") | Some("::1"))
        || host.as_deref().is_some_and(|h| h.starts_with("localhost:"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tree(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("larry-app-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join("public/blog")).unwrap();
        d
    }

    #[test]
    fn wordpress_config_and_debug_hides_the_password() {
        let d = tree("wp");
        std::fs::write(
            d.join("public/wp-config.php"),
            "<?php\n// define('DB_USER', 'old');\ndefine( 'DB_NAME', 'shop' );\ndefine( 'DB_USER', 'shopuser' );\ndefine( 'DB_PASSWORD', 'p\"w$1' );\ndefine('DB_HOST', \"localhost\");\n",
        )
        .unwrap();
        let c = find(&d, "shop").unwrap();
        assert_eq!((c.user.as_str(), c.password.as_str(), c.source.as_str()), ("shopuser", "p\"w$1", "public/wp-config.php"));
        assert!(is_local_host(&c.host));
        assert!(!format!("{c:?}").contains("p\"w"));
        assert!(find(&d, "other").is_none(), "only the config naming this database counts");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn env_files_and_joomla() {
        let d = tree("env");
        std::fs::write(d.join("public/blog/.env"), "DB_DATABASE=blog\nDB_USERNAME=\"bu\"\nDB_PASSWORD='s3 cret' # c\nDB_HOST=db.internal\n").unwrap();
        let c = find(&d, "blog").unwrap();
        assert_eq!((c.user.as_str(), c.password.as_str()), ("bu", "s3 cret"));
        assert!(!is_local_host(&c.host));
        std::fs::write(d.join("public/configuration.php"), "<?php class JConfig {\n public $host = 'localhost';\n public $user = 'ju';\n public $password = 'jp';\n public $db = 'joom';\n}").unwrap();
        assert_eq!(find(&d, "joom").unwrap().user, "ju");
        let _ = std::fs::remove_dir_all(&d);
    }
}
