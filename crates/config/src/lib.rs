//! larry-config: `migration.toml` and `sites.toml` (see docs/spec.md, Configuration).
//!
//! Secrets never live in these files; they only point at 0600 defaults files.

use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

#[derive(Debug)]
pub enum Error {
    Io(String, std::io::Error),
    Parse(String, String),
    Invalid(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(p, e) => write!(f, "{p}: {e}"),
            Error::Parse(p, e) => write!(f, "{p}: {e}"),
            Error::Invalid(m) => write!(f, "{m}"),
        }
    }
}
impl std::error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;

/// Hand-edited files (spreadsheets, Windows editors) may carry CRLF.
fn normalize(text: &str) -> String {
    text.replace("\r\n", "\n")
}

fn read_toml<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T> {
    let p = path.display().to_string();
    let text = std::fs::read_to_string(path).map_err(|e| Error::Io(p.clone(), e))?;
    parse_toml(&text, &p)
}

fn parse_toml<T: for<'de> Deserialize<'de>>(text: &str, origin: &str) -> Result<T> {
    toml::from_str(&normalize(text)).map_err(|e| Error::Parse(origin.to_string(), e.to_string()))
}

// ---------------------------------------------------------------- migration.toml

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MigrationConfig {
    pub version: u32,
    pub source: Source,
    pub ssh: Ssh,
    #[serde(default)]
    pub targets: BTreeMap<String, Target>,
    #[serde(default)]
    pub layout: Layout,
    #[serde(default)]
    pub fpm: Fpm,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Source {
    pub db_defaults_file: String,
    #[serde(default = "default_staging")]
    pub staging_dir: String,
}

fn default_staging() -> String {
    "/var/tmp/larry".into()
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ssh {
    pub config_file: String,
    pub known_hosts: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Target {
    pub host: String,
    pub address: Option<String>,
    pub host_key: String,
    pub transfer_user: String,
    pub incoming_dir: String,
    #[serde(default)]
    pub default: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Layout {
    #[serde(default = "default_vhost_base")]
    pub vhost_base: String,
    #[serde(default = "default_web_group")]
    pub web_group: String,
    pub deploy_acl_user: Option<String>,
}

impl Default for Layout {
    fn default() -> Self {
        Layout { vhost_base: default_vhost_base(), web_group: default_web_group(), deploy_acl_user: None }
    }
}

fn default_vhost_base() -> String {
    "/srv/vhosts".into()
}
fn default_web_group() -> String {
    "www-data".into()
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Fpm {
    #[serde(default)]
    pub defaults: FpmSettings,
}

/// Pool settings; every field optional so layers can be merged.
/// Precedence: built-in defaults < `[fpm.defaults]` < `[site.fpm]`.
#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct FpmSettings {
    pub php_version: Option<String>,
    pub user_pattern: Option<String>,
    pub user: Option<String>,
    pub group: Option<String>,
    pub pm: Option<String>,
    pub max_children: Option<u32>,
    pub process_idle_timeout: Option<String>,
    pub max_requests: Option<u32>,
    #[serde(default)]
    pub php_value: BTreeMap<String, String>,
    #[serde(default)]
    pub php_flag: BTreeMap<String, String>,
}

impl FpmSettings {
    /// `over` wins field by field; maps are merged key by key.
    pub fn merged(&self, over: &FpmSettings) -> FpmSettings {
        fn pick<T: Clone>(a: &Option<T>, b: &Option<T>) -> Option<T> {
            b.clone().or_else(|| a.clone())
        }
        let mut php_value = self.php_value.clone();
        php_value.extend(over.php_value.clone());
        let mut php_flag = self.php_flag.clone();
        php_flag.extend(over.php_flag.clone());
        FpmSettings {
            php_version: pick(&self.php_version, &over.php_version),
            user_pattern: pick(&self.user_pattern, &over.user_pattern),
            user: pick(&self.user, &over.user),
            group: pick(&self.group, &over.group),
            pm: pick(&self.pm, &over.pm),
            max_children: pick(&self.max_children, &over.max_children),
            process_idle_timeout: pick(&self.process_idle_timeout, &over.process_idle_timeout),
            max_requests: pick(&self.max_requests, &over.max_requests),
            php_value,
            php_flag,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ResolvedFpm {
    /// `None` means "the target's default php-fpm"; preflight checks it.
    pub php_version: Option<String>,
    pub user: String,
    pub group: String,
    pub pm: String,
    pub max_children: u32,
    pub process_idle_timeout: String,
    pub max_requests: u32,
    pub php_value: BTreeMap<String, String>,
    pub php_flag: BTreeMap<String, String>,
}

impl MigrationConfig {
    pub fn load(path: &Path) -> Result<Self> {
        let cfg: MigrationConfig = read_toml(path)?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn parse(text: &str) -> Result<Self> {
        let cfg: MigrationConfig = parse_toml(text, "migration.toml")?;
        cfg.validate()?;
        Ok(cfg)
    }

    fn validate(&self) -> Result<()> {
        if self.version != 1 {
            return Err(Error::Invalid(format!("migration.toml: unsupported version {} (expected 1)", self.version)));
        }
        let defaults: Vec<_> = self.targets.iter().filter(|(_, t)| t.default).map(|(n, _)| n.as_str()).collect();
        if defaults.len() > 1 {
            return Err(Error::Invalid(format!("migration.toml: several default targets: {}", defaults.join(", "))));
        }
        for (name, t) in &self.targets {
            if !is_alias(name) {
                return Err(Error::Invalid(format!("migration.toml: bad target name '{name}'")));
            }
            if !t.host_key.starts_with("SHA256:") || t.host_key == "SHA256:..." {
                return Err(Error::Invalid(format!("migration.toml: target '{name}' needs a real host_key (SHA256:...)")));
            }
        }
        Ok(())
    }

    pub fn default_target(&self) -> Option<&str> {
        self.targets.iter().find(|(_, t)| t.default).map(|(n, _)| n.as_str())
    }

    /// Resolve the pool settings for one site.
    pub fn resolve_fpm(&self, site: &Site) -> ResolvedFpm {
        let s = self.fpm.defaults.merged(&site.fpm);
        let pattern = s.user_pattern.clone().unwrap_or_else(|| "php-{domain_dashed}".into());
        let user = s.user.clone().unwrap_or_else(|| pool_user(&site.domain, &pattern));
        let group = s.group.clone().unwrap_or_else(|| user.clone());
        ResolvedFpm {
            php_version: s.php_version,
            user,
            group,
            pm: s.pm.unwrap_or_else(|| "ondemand".into()),
            max_children: s.max_children.unwrap_or(4),
            process_idle_timeout: s.process_idle_timeout.unwrap_or_else(|| "10s".into()),
            max_requests: s.max_requests.unwrap_or(500),
            php_value: s.php_value,
            php_flag: s.php_flag,
        }
    }

    /// `larry config check`: every secret file must exist and be private (no group/other bits).
    pub fn check_secret_files(&self) -> Result<()> {
        check_secret_file(Path::new(&self.source.db_defaults_file))
    }
}

/// Refuse a secrets file that is group- or world-accessible.
pub fn check_secret_file(path: &Path) -> Result<()> {
    let p = path.display().to_string();
    let meta = std::fs::symlink_metadata(path).map_err(|e| Error::Io(p.clone(), e))?;
    if meta.file_type().is_symlink() || !meta.is_file() {
        return Err(Error::Invalid(format!("{p}: secret file must be a regular file")));
    }
    let mode = meta.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(Error::Invalid(format!("{p}: mode {mode:04o} is readable by group or others; chmod 0600")));
    }
    Ok(())
}

// ---------------------------------------------------------------- sites.toml

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SitesFile {
    #[serde(default)]
    pub site: Vec<Site>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Site {
    pub domain: String,
    pub target: Option<String>,
    /// Docroot directory name inside the vhost root (default `public`).
    pub docroot: Option<String>,
    pub db: Option<String>,
    #[serde(default)]
    pub rewrite_paths: bool,
    #[serde(default)]
    pub manage_pool: bool,
    #[serde(default)]
    pub fpm: FpmSettings,
}

impl Site {
    pub fn docroot_name(&self) -> &str {
        self.docroot.as_deref().unwrap_or("public")
    }
}

impl SitesFile {
    pub fn load(path: &Path, cfg: &MigrationConfig) -> Result<Self> {
        let f: SitesFile = read_toml(path)?;
        f.validate(cfg)?;
        Ok(f)
    }

    pub fn parse(text: &str, cfg: &MigrationConfig) -> Result<Self> {
        let f: SitesFile = parse_toml(text, "sites.toml")?;
        f.validate(cfg)?;
        Ok(f)
    }

    fn validate(&self, cfg: &MigrationConfig) -> Result<()> {
        let mut domains = BTreeSet::new();
        let mut users: BTreeMap<String, String> = BTreeMap::new();
        for s in &self.site {
            let d = &s.domain;
            if !is_domain(d) {
                return Err(Error::Invalid(format!("sites.toml: '{d}' is not a usable domain name")));
            }
            if !domains.insert(d.clone()) {
                return Err(Error::Invalid(format!("sites.toml: domain '{d}' listed twice")));
            }
            match s.target.as_deref() {
                Some(t) if !cfg.targets.contains_key(t) => return Err(Error::Invalid(format!("sites.toml: {d}: unknown target '{t}'"))),
                None if cfg.default_target().is_none() => return Err(Error::Invalid(format!("sites.toml: {d}: no target and no default target"))),
                _ => {}
            }
            if let Some(db) = &s.db {
                if !is_db_name(db) {
                    return Err(Error::Invalid(format!("sites.toml: {d}: '{db}' is not a plain database name")));
                }
            }
            let dr = s.docroot_name();
            if !is_path_component(dr) {
                return Err(Error::Invalid(format!("sites.toml: {d}: docroot '{dr}' must be a single directory name")));
            }
            let user = cfg.resolve_fpm(s).user;
            if user.len() > 32 {
                return Err(Error::Invalid(format!("sites.toml: {d}: pool user '{user}' is longer than 32 characters")));
            }
            if let Some(other) = users.insert(user.clone(), d.clone()) {
                return Err(Error::Invalid(format!("sites.toml: {d} and {other} would share pool user '{user}'")));
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------- naming rules

/// Same rule as the old manifest builder: what the tools can carry safely.
pub fn is_domain(s: &str) -> bool {
    let b = s.as_bytes();
    !b.is_empty()
        && !s.contains("..")
        && b[0].is_ascii_alphanumeric()
        && b[b.len() - 1].is_ascii_alphanumeric()
        && b.iter().all(|c| c.is_ascii_alphanumeric() || *c == b'.' || *c == b'-')
}

pub fn is_db_name(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
}

fn is_alias(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'.' || c == b'_' || c == b'-')
}

fn is_path_component(s: &str) -> bool {
    !s.is_empty() && s != "." && s != ".." && s.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'.' || c == b'_' || c == b'-')
}

/// Lowercase, runs of anything but a-z0-9 become one dash, no leading/trailing dash
/// (`sanitize_pool_name` in create-apache-vhost.sh).
pub fn dashed(domain: &str) -> String {
    let mut out = String::new();
    for c in domain.to_ascii_lowercase().chars() {
        if c.is_ascii_alphanumeric() {
            out.push(c);
        } else if !out.ends_with('-') {
            out.push('-');
        }
    }
    out.trim_matches('-').to_string()
}

/// Pool user for a domain. Over 32 characters it is cut to 23, then `-` and 8 hex
/// characters of a hash of the domain, as create-apache-vhost.sh does, so distinct
/// domains stay distinct. (The script hashes with md5, larry with sha256: only
/// users larry creates get larry's suffix; an existing vhost's pool is found via its socket.)
pub fn pool_user(domain: &str, pattern: &str) -> String {
    let name = pattern.replace("{domain_dashed}", &dashed(domain)).replace("{domain}", domain);
    if name.len() <= 32 {
        return name;
    }
    let hash = Sha256::digest(domain.as_bytes());
    let suffix: String = hash.iter().take(4).map(|b| format!("{b:02x}")).collect();
    let head: String = name.chars().take(23).collect();
    format!("{head}-{suffix}")
}

#[cfg(test)]
mod tests {
    use super::*;

    const CFG: &str = r#"
version = 1
[source]
db_defaults_file = "/root/migration-db.cnf"
[ssh]
config_file = "/root/larry/ssh_config"
known_hosts = "/root/larry/known_hosts"
[targets.web1]
host = "web1.example.net"
host_key = "SHA256:abc"
transfer_user = "migrate"
incoming_dir = "/srv/migration-incoming"
default = true
[fpm.defaults]
php_version = "8.3"
max_children = 4
"#;

    const SITES: &str = r#"
[[site]]
domain = "shop.example.org"
docroot = "public"
db = "shop_db"
[site.fpm]
max_children = 8
php_value = { memory_limit = "256M" }

[[site]]
domain = "blog.example.org"
"#;

    #[test]
    fn crlf_parses_like_lf() {
        let lf = MigrationConfig::parse(CFG).unwrap();
        let crlf = MigrationConfig::parse(&CFG.replace('\n', "\r\n")).unwrap();
        assert_eq!(lf.targets["web1"].host, crlf.targets["web1"].host);
        let a = SitesFile::parse(SITES, &lf).unwrap();
        let b = SitesFile::parse(&SITES.replace('\n', "\r\n"), &lf).unwrap();
        assert_eq!(a.site.len(), b.site.len());
        assert_eq!(a.site[0].fpm, b.site[0].fpm);
    }

    #[test]
    fn fpm_precedence() {
        let cfg = MigrationConfig::parse(CFG).unwrap();
        let sites = SitesFile::parse(SITES, &cfg).unwrap();
        let shop = cfg.resolve_fpm(&sites.site[0]);
        let blog = cfg.resolve_fpm(&sites.site[1]);
        assert_eq!(shop.max_children, 8);
        assert_eq!(blog.max_children, 4);
        assert_eq!(shop.pm, "ondemand");
        assert_eq!(shop.user, "php-shop-example-org");
        assert_eq!(shop.php_value["memory_limit"], "256M");
        assert_eq!(shop.php_version.as_deref(), Some("8.3"));
    }

    #[test]
    fn long_pool_user_is_cut_and_unique() {
        let a = pool_user("a-very-long-subdomain-name.example.organisation", "php-{domain_dashed}");
        let b = pool_user("a-very-long-subdomain-name.example.organisations", "php-{domain_dashed}");
        assert_eq!(a.len(), 32);
        assert_eq!(b.len(), 32);
        assert_ne!(a, b);
        assert_eq!(&a[23..24], "-");
        assert_eq!(dashed("Shop_1..Example.ORG"), "shop-1-example-org");
    }

    #[test]
    fn rejects_typos_and_bad_values() {
        assert!(MigrationConfig::parse(&CFG.replace("max_children", "max_childs")).is_err());
        assert!(MigrationConfig::parse(&CFG.replace("version = 1", "version = 2")).is_err());
        assert!(MigrationConfig::parse(&CFG.replace("SHA256:abc", "SHA256:...")).is_err());
        let cfg = MigrationConfig::parse(CFG).unwrap();
        for bad in [
            "[[site]]\ndomain = \"a,b.de\"\n",
            "[[site]]\ndomain = \"a.de\"\ntarget = \"nope\"\n",
            "[[site]]\ndomain = \"a.de\"\ndb = \"x; drop\"\n",
            "[[site]]\ndomain = \"a.de\"\ndocroot = \"../x\"\n",
            "[[site]]\ndomain = \"a.de\"\n[[site]]\ndomain = \"a.de\"\n",
        ] {
            assert!(SitesFile::parse(bad, &cfg).is_err(), "accepted: {bad}");
        }
    }

    #[test]
    fn secret_file_permissions() {
        let dir = std::env::temp_dir().join(format!("larry-cfg-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("db.cnf");
        std::fs::write(&f, "[client]\n").unwrap();
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o640)).unwrap();
        assert!(check_secret_file(&f).is_err());
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(check_secret_file(&f).is_ok());
        assert!(check_secret_file(&dir.join("missing")).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
