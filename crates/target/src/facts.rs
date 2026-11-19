//! `preflight.json`: what the source tells a target before anything is copied, so `target preflight`
//! can look for conflicts and unsupported collations. Untrusted input: validated like the manifest.

use crate::manifest::{FpmManifest, Manifest, MANIFEST_VERSION};
use crate::provision::{self, Env};
use crate::{apply, pool, vhost};
use larry_config::{is_db_name, is_domain};
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SiteFact {
    pub domain: String,
    #[serde(default)]
    pub aliases: Vec<String>,
    pub docroot: String,
    pub pool_user: String,
    pub pool_group: String,
    pub php_version: Option<String>,
    pub php: bool,
    pub db: Option<String>,
    #[serde(default)]
    pub manage_pool: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Facts {
    pub version: u32,
    pub sites: Vec<SiteFact>,
    /// Collations the sites' databases use on the source.
    #[serde(default)]
    pub collations: Vec<String>,
}

pub const FILE_NAME: &str = "preflight.json";

impl Facts {
    pub fn parse(text: &str) -> Result<Facts, String> {
        let f: Facts = serde_json::from_str(text).map_err(|e| format!("{FILE_NAME}: {e}"))?;
        if f.version != 1 {
            return Err(format!("{FILE_NAME}: unsupported version {}", f.version));
        }
        for c in &f.collations {
            if c.is_empty() || !c.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
                return Err(format!("{FILE_NAME}: bad collation name '{c}'"));
            }
        }
        for s in &f.sites {
            if !is_domain(&s.domain) || s.aliases.iter().any(|a| !is_domain(a)) || s.db.as_deref().is_some_and(|d| !is_db_name(d)) {
                return Err(format!("{FILE_NAME}: bad site entry '{}'", s.domain));
            }
            // reuse the manifest rules for users, docroot and php version
            to_manifest(s).validate()?;
        }
        Ok(f)
    }

    pub fn read(env: &Env) -> Result<Option<Facts>, String> {
        let p = env.incoming.join(FILE_NAME);
        match std::fs::symlink_metadata(&p) {
            Err(_) => Ok(None),
            Ok(m) if m.is_file() && m.len() < 4 << 20 => Facts::parse(&std::fs::read_to_string(&p).map_err(|e| format!("{}: {e}", p.display()))?).map(Some),
            Ok(_) => Err(format!("{}: not a regular file", p.display())),
        }
    }
}

pub fn to_manifest(s: &SiteFact) -> Manifest {
    Manifest {
        version: MANIFEST_VERSION,
        domain: s.domain.clone(),
        aliases: s.aliases.clone(),
        docroot: s.docroot.clone(),
        source_vhost_root: None,
        source_docroot: None,
        db: s.db.clone(),
        rewrite_paths: false,
        manage_pool: s.manage_pool,
        php: s.php,
        tls: vec![],
        fpm: FpmManifest {
            php_version: s.php_version.clone(),
            user: s.pool_user.clone(),
            group: s.pool_group.clone(),
            pm: "ondemand".into(),
            max_children: 4,
            process_idle_timeout: "10s".into(),
            max_requests: 500,
            php_value: Default::default(),
            php_flag: Default::default(),
        },
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Level {
    Ok,
    Warn,
    Fail,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Finding {
    pub level: Level,
    pub site: String,
    pub text: String,
}

/// (pool section, user, file) of every pool file below `php_etc`.
fn pools(php_etc: &Path) -> Vec<(String, String, std::path::PathBuf)> {
    let mut v = vec![];
    let Ok(rd) = std::fs::read_dir(php_etc) else { return v };
    for e in rd.flatten() {
        let Ok(files) = std::fs::read_dir(e.path().join("fpm/pool.d")) else { continue };
        for f in files.flatten().map(|f| f.path()).filter(|p| p.extension().is_some_and(|x| x == "conf")) {
            let Ok(t) = std::fs::read_to_string(&f) else { continue };
            let section = t.lines().find_map(|l| l.trim().strip_prefix('[').and_then(|r| r.strip_suffix(']')).map(String::from)).unwrap_or_default();
            if let Some(u) = pool::ini_value(&t, "user") {
                v.push((section, u, f));
            }
        }
    }
    v
}

/// Names that another vhost already serves.
fn served_elsewhere(sites_dir: &Path, domain: &str, own_conf: &str) -> Vec<String> {
    let re = regex::Regex::new(r"(?im)^\s*Server(?:Name|Alias)\s+(.+)$").unwrap();
    let mut v = vec![];
    let Ok(rd) = std::fs::read_dir(sites_dir) else { return v };
    for e in rd.flatten() {
        let name = e.file_name().to_string_lossy().to_string();
        if name == own_conf || name == format!("{domain}-le-ssl.conf") || !name.ends_with(".conf") {
            continue;
        }
        let Ok(t) = std::fs::read_to_string(e.path()) else { continue };
        if re.captures_iter(&t).any(|c| c[1].split_whitespace().any(|h| h.eq_ignore_ascii_case(domain))) {
            v.push(name);
        }
    }
    v
}

/// Name and ownership conflicts on this target, from the filesystem only.
pub fn conflicts(facts: &Facts, env: &Env) -> Vec<Finding> {
    let mut out = vec![];
    let existing_pools = pools(&env.php_etc);
    for s in &facts.sites {
        let mut add = |level, text: String| out.push(Finding { level, site: s.domain.clone(), text });
        let m = to_manifest(s);
        let pool_name = pool::pool_name(&m);
        // another site already answers for this name
        let own = vhost::conf_name(&s.domain);
        for f in served_elsewhere(&env.apache_sites, &s.domain, &own) {
            add(Level::Fail, format!("{} already serves {}; two vhosts would claim it", f, s.domain));
        }
        // pool user and pool name
        for (section, user, file) in &existing_pools {
            let ours = file.file_name().is_some_and(|n| n.to_string_lossy() == format!("{pool_name}.conf"));
            if *user == s.pool_user && !ours && *section != pool_name {
                add(Level::Fail, format!("pool user {user} is already used by pool [{section}] ({}); each site needs its own", file.display()));
            }
            if *section == pool_name && *user != s.pool_user {
                add(Level::Fail, format!("pool [{pool_name}] already exists ({}) with user {user}, not {}", file.display(), s.pool_user));
            }
        }
        // the vhost directory and an existing vhost
        match provision::resolve(&m, env, s.php_version.as_deref().unwrap_or("0")) {
            Err(e) => add(Level::Fail, e),
            Ok(r) if r.adopted.is_some() => {
                add(Level::Warn, format!("a vhost exists and will be adopted (pool user {}); its pool is left alone unless manage_pool is set", r.pool_user))
            }
            Ok(r) => {
                if r.vhost_root.is_dir() {
                    let foreign = apply::foreign_owners(&r.vhost_root, &[], &r.pool_user);
                    if foreign.is_empty() {
                        add(Level::Ok, format!("{} exists and holds no other site's files", r.vhost_root.display()));
                    } else {
                        add(
                            Level::Fail,
                            format!(
                                "{} holds files owned by another site's pool user ({}); `target apply --adopt` is needed if they are stale",
                                r.vhost_root.display(),
                                foreign.join(", ")
                            ),
                        );
                    }
                } else {
                    add(Level::Ok, format!("{} is free", r.vhost_root.display()));
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn env(tag: &str) -> (Env, PathBuf) {
        let d = std::env::temp_dir().join(format!("larry-facts-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        for s in ["vhosts", "sites", "php/8.3/fpm/pool.d", "incoming"] {
            std::fs::create_dir_all(d.join(s)).unwrap();
        }
        let e = Env {
            vhost_base: d.join("vhosts"),
            apache_sites: d.join("sites"),
            php_etc: d.join("php"),
            letsencrypt: d.join("le"),
            incoming: d.join("incoming"),
            backup_dir: d.join("bak"),
            web_group: "www-data".into(),
            deploy_user: None,
        };
        (e, d)
    }

    fn fact() -> SiteFact {
        SiteFact {
            domain: "shop.example.org".into(),
            aliases: vec![],
            docroot: "public".into(),
            pool_user: "php-shop-example-org".into(),
            pool_group: "php-shop-example-org".into(),
            php_version: Some("8.3".into()),
            php: true,
            db: Some("shop".into()),
            manage_pool: false,
        }
    }

    fn facts() -> Facts {
        Facts { version: 1, sites: vec![fact()], collations: vec!["utf8mb4_general_ci".into()] }
    }

    #[test]
    fn untrusted_facts_are_validated() {
        let ok = serde_json::to_string(&facts()).unwrap();
        assert!(Facts::parse(&ok).is_ok());
        let bad = ok.replace("utf8mb4_general_ci", "x'; DROP");
        assert!(Facts::parse(&bad).is_err());
        assert!(Facts::parse(&ok.replace("shop.example.org", "../x")).is_err());
        assert!(Facts::parse(&ok.replace("php-shop-example-org", "Root;")).is_err());
    }

    #[test]
    fn a_clean_target_has_no_conflicts() {
        let (e, d) = env("clean");
        let f = conflicts(&facts(), &e);
        assert!(f.iter().all(|x| x.level == Level::Ok), "{f:?}");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn name_clashes_are_found() {
        let (e, d) = env("clash");
        // another vhost already serves the name
        std::fs::write(e.apache_sites.join("old.conf"), "ServerName old.example.org\nServerAlias shop.example.org\n").unwrap();
        // the pool user belongs to a different pool
        std::fs::write(e.php_etc.join("8.3/fpm/pool.d/other.conf"), "[other]\nuser = php-shop-example-org\nlisten = /run/php/o.sock\n").unwrap();
        let t: Vec<String> = conflicts(&facts(), &e).into_iter().filter(|f| f.level == Level::Fail).map(|f| f.text).collect();
        assert!(t.iter().any(|x| x.contains("old.conf already serves")), "{t:?}");
        assert!(t.iter().any(|x| x.contains("already used by pool [other]")), "{t:?}");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn an_existing_pool_with_our_name_but_another_user_fails_and_our_own_is_fine() {
        let (e, d) = env("pool");
        let p = e.php_etc.join("8.3/fpm/pool.d/shop-example-org.conf");
        std::fs::write(&p, "[shop-example-org]\nuser = someone\nlisten = /x.sock\n").unwrap();
        assert!(conflicts(&facts(), &e).iter().any(|f| f.level == Level::Fail && f.text.contains("with user someone")));
        std::fs::write(&p, "[shop-example-org]\nuser = php-shop-example-org\nlisten = /x.sock\n").unwrap();
        assert!(conflicts(&facts(), &e).iter().all(|f| f.level != Level::Fail));
        let _ = std::fs::remove_dir_all(&d);
    }
}
