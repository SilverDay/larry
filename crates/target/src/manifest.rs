//! `manifest.json`: what the source tells the target about one site. It travels through the drop
//! directory, so the target treats it as untrusted input and validates every field before use.

use larry_config::{is_db_name, is_domain};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FpmManifest {
    pub php_version: Option<String>,
    pub user: String,
    pub group: String,
    pub pm: String,
    pub max_children: u32,
    pub process_idle_timeout: String,
    pub max_requests: u32,
    #[serde(default)]
    pub php_value: BTreeMap<String, String>,
    #[serde(default)]
    pub php_flag: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Manifest {
    pub version: u32,
    pub domain: String,
    #[serde(default)]
    pub aliases: Vec<String>,
    /// Docroot directory name on the target (inside the vhost root).
    pub docroot: String,
    /// Absolute paths on the source, for path rewriting and reports.
    pub source_vhost_root: Option<String>,
    pub source_docroot: Option<String>,
    pub db: Option<String>,
    #[serde(default)]
    pub rewrite_paths: bool,
    #[serde(default)]
    pub manage_pool: bool,
    #[serde(default)]
    pub php: bool,
    /// Let's Encrypt certificate names (`/etc/letsencrypt/live/<name>`) this site uses.
    #[serde(default)]
    pub tls: Vec<String>,
    pub fpm: FpmManifest,
}

pub const MANIFEST_VERSION: u32 = 1;

fn is_unix_name(s: &str) -> bool {
    let b = s.as_bytes();
    !b.is_empty()
        && b.len() <= 32
        && (b[0].is_ascii_lowercase() || b[0] == b'_')
        && b.iter().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'_' || *c == b'-')
}

/// A name usable as a php.ini key or a certbot lineage name: no whitespace, brackets, `=` or newlines.
fn is_key(s: &str) -> bool {
    !s.is_empty() && s.len() <= 100 && s.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'.' || c == b'-')
}

/// Values go into a pool file line: no control characters, so nothing can start a new directive.
fn is_value(s: &str) -> bool {
    s.len() <= 1000 && !s.chars().any(|c| c.is_control())
}

fn is_component(s: &str) -> bool {
    !s.is_empty() && s != "." && s != ".." && s.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'.' || c == b'_' || c == b'-')
}

impl Manifest {
    pub fn parse(text: &str) -> Result<Manifest, String> {
        let m: Manifest = serde_json::from_str(text).map_err(|e| format!("manifest.json: {e}"))?;
        m.validate()?;
        Ok(m)
    }

    pub fn validate(&self) -> Result<(), String> {
        let d = &self.domain;
        if self.version != MANIFEST_VERSION {
            return Err(format!("manifest.json: unsupported version {}", self.version));
        }
        if !is_domain(d) {
            return Err(format!("manifest.json: '{d}' is not a usable domain name"));
        }
        for a in &self.aliases {
            if !is_domain(a) {
                return Err(format!("{d}: bad alias '{a}'"));
            }
        }
        if !is_component(&self.docroot) {
            return Err(format!("{d}: bad docroot '{}'", self.docroot));
        }
        if let Some(db) = &self.db {
            if !is_db_name(db) {
                return Err(format!("{d}: bad database name '{db}'"));
            }
        }
        for t in &self.tls {
            if !is_key(t) {
                return Err(format!("{d}: bad certificate name '{t}'"));
            }
        }
        let f = &self.fpm;
        if !is_unix_name(&f.user) || !is_unix_name(&f.group) {
            return Err(format!("{d}: bad pool user/group '{}'/'{}'", f.user, f.group));
        }
        if let Some(v) = &f.php_version {
            if v.is_empty() || !v.bytes().all(|c| c.is_ascii_digit() || c == b'.') {
                return Err(format!("{d}: bad php version '{v}'"));
            }
        }
        if !matches!(f.pm.as_str(), "static" | "dynamic" | "ondemand") {
            return Err(format!("{d}: bad pm '{}'", f.pm));
        }
        if f.max_children == 0 || f.max_children > 1000 {
            return Err(format!("{d}: bad pm.max_children {}", f.max_children));
        }
        if !f.process_idle_timeout.bytes().all(|c| c.is_ascii_alphanumeric()) || f.process_idle_timeout.is_empty() {
            return Err(format!("{d}: bad pm.process_idle_timeout '{}'", f.process_idle_timeout));
        }
        for (k, v) in f.php_value.iter().chain(f.php_flag.iter()) {
            if !is_key(k) || !is_value(v) {
                return Err(format!("{d}: bad php setting '{k}'"));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
pub(crate) fn sample() -> Manifest {
    Manifest {
        version: 1,
        domain: "shop.example.org".into(),
        aliases: vec!["www.shop.example.org".into()],
        docroot: "public".into(),
        source_vhost_root: Some("/var/www/shop".into()),
        source_docroot: Some("/var/www/shop/httpdocs".into()),
        db: Some("shop".into()),
        rewrite_paths: false,
        manage_pool: false,
        php: true,
        tls: vec!["shop.example.org".into()],
        fpm: FpmManifest {
            php_version: Some("8.3".into()),
            user: "php-shop-example-org".into(),
            group: "php-shop-example-org".into(),
            pm: "ondemand".into(),
            max_children: 4,
            process_idle_timeout: "10s".into(),
            max_requests: 500,
            php_value: BTreeMap::new(),
            php_flag: BTreeMap::new(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_and_validation() {
        let m = sample();
        let back = Manifest::parse(&serde_json::to_string(&m).unwrap()).unwrap();
        assert_eq!(back, m);
        let bad = |f: &dyn Fn(&mut Manifest)| {
            let mut m = sample();
            f(&mut m);
            assert!(m.validate().is_err());
        };
        bad(&|m| m.domain = "../etc".into());
        bad(&|m| m.docroot = "../x".into());
        bad(&|m| m.db = Some("a b".into()));
        bad(&|m| m.fpm.user = "Root;".into());
        bad(&|m| m.fpm.pm = "x".into());
        bad(&|m| m.tls = vec!["../../etc".into()]);
        // a newline would start a new pool directive
        bad(&|m| {
            m.fpm.php_value.insert("memory_limit".into(), "1G\nuser = root".into());
        });
        bad(&|m| {
            m.fpm.php_flag.insert("a]\nb".into(), "on".into());
        });
    }
}
