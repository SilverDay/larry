//! `larry preflight` (source) and `larry target preflight` (target, root).
//! Read-only: reports what would stop a migration before anything is copied.

use larry_config::MigrationConfig;
use larry_db::{MysqlCli, Sql};
use larry_target::facts::{self, Facts, SiteFact};
use larry_target::provision::Env;
use larry_transport::ssh;
use larry_transport::transfer::{check_tools, rsync_probe, ToolSpec, ToolStatus, SOURCE_TOOLS, TARGET_TOOLS};
use std::path::{Path, PathBuf};

pub struct Report {
    pub lines: Vec<String>,
    pub failed: bool,
}

impl Report {
    fn new() -> Self {
        Report { lines: vec![], failed: false }
    }
    fn ok(&mut self, what: &str, detail: &str) {
        self.lines.push(format!("ok    {what}{}", if detail.is_empty() { String::new() } else { format!(": {detail}") }));
    }
    fn warn(&mut self, what: &str, detail: &str) {
        self.lines.push(format!("warn  {what}: {detail}"));
    }
    fn fail(&mut self, what: &str, detail: &str) {
        self.failed = true;
        self.lines.push(format!("FAIL  {what}: {detail}"));
    }
    pub fn text(&self) -> String {
        self.lines.join("\n") + "\n"
    }
}

fn tools(r: &mut Report, specs: &[ToolSpec]) {
    for ToolStatus { label, found, version } in check_tools(specs) {
        match found {
            Some(f) => r.ok(label, &format!("{f}{}", version.map(|v| format!(" ({v})")).unwrap_or_default())),
            None => r.fail(label, "not found"),
        }
    }
}

type CollationsOf<'a> = dyn Fn(&[String]) -> Result<Vec<String>, String> + 'a;

/// What each target needs to know before the first copy: the planned sites and the collations their
/// databases use. Built from `sites.toml` and the inventory; empty when there is no plan yet.
pub fn build_facts(cfg: &MigrationConfig, dir: &Path, collations_of: &CollationsOf) -> Result<Vec<(String, Facts)>, String> {
    let sites_path = dir.join("sites.toml");
    if !sites_path.is_file() {
        return Ok(vec![]);
    }
    let sites = larry_config::SitesFile::load(&sites_path, cfg).map_err(|e| e.to_string())?;
    let records = larry_discover::read_inventory(&dir.join("inventory.jsonl")).unwrap_or_default();
    let mut by_target: std::collections::BTreeMap<String, Vec<SiteFact>> = Default::default();
    for s in &sites.site {
        let Some(t) = s.target.clone().or_else(|| cfg.default_target().map(String::from)) else { continue };
        let f = cfg.resolve_fpm(s);
        let rec = records.iter().find(|r| r.domain == s.domain);
        by_target.entry(t).or_default().push(SiteFact {
            domain: s.domain.clone(),
            aliases: rec.map(|r| r.aliases.clone()).unwrap_or_default(),
            docroot: s.docroot_name().to_string(),
            pool_user: f.user,
            pool_group: f.group,
            php_version: f.php_version,
            php: rec.is_none_or(|r| r.php_mode == "fpm" || r.php_mode == "mod_php"),
            db: s.db.clone(),
            manage_pool: s.manage_pool,
        });
    }
    let mut out = vec![];
    for (t, sites) in by_target {
        let dbs: Vec<String> = sites.iter().filter_map(|s| s.db.clone()).collect();
        let collations = if dbs.is_empty() { vec![] } else { collations_of(&dbs)? };
        out.push((t, Facts { version: 1, sites, collations }));
    }
    Ok(out)
}

/// Source side: tools, config and secret files, pinned host keys, database access, reachability.
pub fn source(cfg: &MigrationConfig, dir: &Path) -> Report {
    let mut r = Report::new();
    tools(&mut r, SOURCE_TOOLS);

    match cfg.check_secret_files() {
        Ok(()) => r.ok("secret files", &cfg.source.db_defaults_file),
        Err(e) => r.fail("secret files", &e.to_string()),
    }
    match MysqlCli::new(cfg.source.db_defaults_file.clone().into()).and_then(|m| m.query("SELECT 1")) {
        Ok(_) => r.ok("database access", "read-only account can connect"),
        Err(e) => r.fail("database access", &e),
    }

    for p in [&cfg.ssh.config_file, &cfg.ssh.known_hosts] {
        if Path::new(p).is_file() {
            r.ok("file", p)
        } else {
            r.fail("file", &format!("{p} is missing (run `larry init`)"))
        }
    }
    let known = std::fs::read_to_string(&cfg.ssh.known_hosts).unwrap_or_default();
    let probe_dir = std::env::temp_dir().join(format!("larry-probe-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&probe_dir);
    for (name, t) in &cfg.targets {
        let addr = t.address.as_deref().unwrap_or(&t.host);
        // the pinned key must be the one `migration.toml` says the admin confirmed
        let known_name = ssh::known_hosts_name(addr, t.port);
        match known.lines().find(|l| l.split_whitespace().next() == Some(known_name.as_str())) {
            None => r.fail(&format!("host key {name}"), &format!("no pinned key for {known_name} in {}", cfg.ssh.known_hosts)),
            Some(l) => match ssh::fingerprint(l) {
                Ok(fp) if fp == t.host_key => r.ok(&format!("host key {name}"), &fp),
                Ok(fp) => r.fail(&format!("host key {name}"), &format!("known_hosts has {fp}, migration.toml says {}", t.host_key)),
                Err(e) => r.fail(&format!("host key {name}"), &e),
            },
        }
        match rsync_probe(&cfg.ssh.config_file, name, &probe_dir, "./").and_then(|c| c.run().map_err(|e| e.to_string())) {
            Ok(o) if o.success() => r.ok(&format!("reachable {name}"), "dry-run into the drop directory works"),
            Ok(o) => r.fail(&format!("reachable {name}"), o.stderr.trim()),
            Err(e) => r.fail(&format!("reachable {name}"), &e),
        }
    }
    let _ = std::fs::remove_dir_all(&probe_dir);
    push_facts(&mut r, cfg, dir);
    r
}

/// Hand the facts to each target through the drop directory, where `larry target preflight` reads them.
fn push_facts(r: &mut Report, cfg: &MigrationConfig, dir: &Path) {
    let sql = MysqlCli::new(cfg.source.db_defaults_file.clone().into());
    let collations_of = |dbs: &[String]| -> Result<Vec<String>, String> {
        let refs: Vec<&str> = dbs.iter().map(String::as_str).collect();
        Ok(larry_db::checks::collations_used(sql.as_ref().map_err(|e| e.clone())?, &refs)?.into_iter().collect())
    };
    let all = match build_facts(cfg, dir, &collations_of) {
        Ok(a) => a,
        Err(e) => return r.fail("facts for the targets", &e),
    };
    if all.is_empty() {
        r.warn("facts for the targets", "no sites.toml yet (run `larry plan`); conflicts and collations are checked after that");
        return;
    }
    let stage = std::env::temp_dir().join(format!("larry-facts-{}", std::process::id()));
    for (t, f) in all {
        let res = (|| -> Result<(), String> {
            std::fs::create_dir_all(&stage).map_err(|e| e.to_string())?;
            let file = stage.join(facts::FILE_NAME);
            std::fs::write(&file, serde_json::to_string_pretty(&f).map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
            let c = larry_transport::transfer::rsync_push(&cfg.ssh.config_file, &t, &[file.as_path()], "./")?;
            c.run_checked().map_err(|e| e.to_string())?;
            Ok(())
        })();
        match res {
            Ok(()) => r.ok(
                &format!("facts for {t}"),
                &format!("{} site(s), {} collation(s) handed over; run `larry target preflight` there", f.sites.len(), f.collations.len()),
            ),
            Err(e) => r.fail(&format!("facts for {t}"), &e),
        }
    }
    let _ = std::fs::remove_dir_all(&stage);
}

/// Target side, run by an admin as root: tools, requested PHP-FPM versions, free space.
pub fn target(php_versions: &[String], vhost_base: &Path, incoming: &Path, db_defaults: Option<&Path>) -> Report {
    let mut r = Report::new();
    tools(&mut r, TARGET_TOOLS);
    let env = Env {
        vhost_base: vhost_base.into(),
        apache_sites: "/etc/apache2/sites-available".into(),
        php_etc: "/etc/php".into(),
        letsencrypt: "/etc/letsencrypt".into(),
        incoming: incoming.into(),
        backup_dir: PathBuf::from("/var/backups/larry"),
        web_group: "www-data".into(),
        deploy_user: None,
    };
    let facts = Facts::read(&env);
    let mut php_versions = php_versions.to_vec();
    if let Ok(Some(f)) = &facts {
        for v in f.sites.iter().filter_map(|s| s.php_version.clone()) {
            if !php_versions.contains(&v) {
                php_versions.push(v);
            }
        }
    }
    for v in &php_versions {
        if !v.bytes().all(|c| c.is_ascii_digit() || c == b'.') || v.is_empty() {
            r.fail("php-fpm", &format!("'{v}' is not a version like 8.3"));
            continue;
        }
        let bin = format!("php-fpm{v}");
        if larry_transport::transfer::locate(&[bin.as_str()]).is_some() {
            r.ok(&format!("php-fpm {v}"), &bin);
        } else {
            r.fail(&format!("php-fpm {v}"), &format!("{bin} is not installed"));
        }
    }
    for (what, dir) in [("vhost base", vhost_base), ("drop directory", incoming)] {
        match larry_transport::Cmd::new("df").args(["-Pk"]).arg(dir).run() {
            Ok(o) if o.success() => {
                let avail_kb: Option<u64> = o.stdout.lines().nth(1).and_then(|l| l.split_whitespace().nth(3)).and_then(|v| v.parse().ok());
                match avail_kb {
                    Some(kb) => r.ok(what, &format!("{} free in {}", human(kb * 1024), dir.display())),
                    None => r.fail(what, "could not read free space"),
                }
            }
            _ => r.fail(what, &format!("{} does not exist", dir.display())),
        }
    }
    match facts {
        Err(e) => r.fail("facts from the source", &e),
        Ok(None) => {
            r.warn("facts from the source", "no preflight.json in the drop directory; run `larry preflight` on the source to check conflicts and collations")
        }
        Ok(Some(f)) => target_facts(&mut r, &f, &env, db_defaults),
    }
    r
}

fn target_facts(r: &mut Report, f: &Facts, env: &Env, db_defaults: Option<&Path>) {
    for c in facts::conflicts(f, env) {
        let what = format!("site {}", c.site);
        match c.level {
            facts::Level::Ok => r.ok(&what, &c.text),
            facts::Level::Warn => r.warn(&what, &c.text),
            facts::Level::Fail => r.fail(&what, &c.text),
        }
    }
    let Some(defaults) = db_defaults else {
        if !f.collations.is_empty() || f.sites.iter().any(|s| s.db.is_some()) {
            r.warn("database", "no --db-defaults-file: collations and existing databases not checked");
        }
        return;
    };
    let sql = match larry_config::check_secret_file(defaults).map_err(|e| e.to_string()).and_then(|_| MysqlCli::new(defaults.into())) {
        Ok(s) => s,
        Err(e) => return r.fail("database", &e),
    };
    if let Err(e) = sql.query("SELECT 1") {
        return r.fail("database", &format!("admin account cannot connect: {e}"));
    }
    r.ok("database", "admin account can connect");
    match larry_db::checks::collations_available(&sql) {
        Ok(avail) => {
            let used = f.collations.iter().cloned().collect();
            let missing = larry_db::checks::missing_collations(&used, &avail);
            if missing.is_empty() {
                r.ok("collations", &format!("all {} collation(s) of the source databases exist here", f.collations.len()));
            }
            for m in missing {
                r.fail("collations", &format!("{m} is used on the source but this server does not have it (MySQL 8 to MariaDB?); the import would fail"));
            }
        }
        Err(e) => r.fail("collations", &e),
    }
    for s in &f.sites {
        let Some(db) = &s.db else { continue };
        if !larry_config::is_db_name(db) {
            continue;
        }
        let n = sql.query(&format!("SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA='{db}' AND TABLE_TYPE='BASE TABLE'")).unwrap_or_default();
        match n.trim().parse::<u64>() {
            Ok(0) => r.ok(&format!("database {db}"), "free"),
            Ok(n) => r.warn(&format!("database {db}"), &format!("exists with {n} table(s); `target apply` dumps it to the backup directory, then replaces it")),
            Err(_) => r.fail(&format!("database {db}"), "could not count tables"),
        }
    }
}

fn human(bytes: u64) -> String {
    let (mut v, mut i) = (bytes as f64, 0);
    while v >= 1024.0 && i < 4 {
        v /= 1024.0;
        i += 1;
    }
    format!("{v:.1} {}", ["B", "KiB", "MiB", "GiB", "TiB"][i])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_report_flags_missing_php_and_paths() {
        let r = target(&["99.9".into(), "x;y".into()], Path::new("/definitely/not/here"), Path::new("/tmp"), None);
        assert!(r.failed);
        let t = r.text();
        assert!(t.contains("FAIL  php-fpm 99.9") && t.contains("FAIL  php-fpm: 'x;y'") && t.contains("FAIL  vhost base"));
        assert!(t.contains("ok    drop directory") && t.contains("free in /tmp"));
    }

    #[test]
    fn facts_are_built_per_target_from_the_plan() {
        let d = std::env::temp_dir().join(format!("larry-pf-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        let cfg = MigrationConfig::parse(
            "version = 1\n[source]\ndb_defaults_file = \"/x\"\n[ssh]\nconfig_file = \"/c\"\nknown_hosts = \"/k\"\n[targets.web1]\nhost = \"h\"\nhost_key = \"SHA256:abc\"\ntransfer_user = \"m\"\nincoming_dir = \"/in\"\ndefault = true\n[targets.web2]\nhost = \"h2\"\nhost_key = \"SHA256:abd\"\ntransfer_user = \"m\"\nincoming_dir = \"/in\"\n",
        )
        .unwrap();
        std::fs::write(d.join("sites.toml"), "[[site]]\ndomain = \"a.example.org\"\ndb = \"a\"\n[[site]]\ndomain = \"b.example.org\"\ntarget = \"web2\"\n")
            .unwrap();
        let none = build_facts(&cfg, &d.join("missing"), &|_| Ok(vec![])).unwrap();
        assert!(none.is_empty(), "no plan, no facts");
        let all = build_facts(&cfg, &d, &|dbs| Ok(dbs.iter().map(|_| "utf8mb4_general_ci".to_string()).collect())).unwrap();
        assert_eq!(all.len(), 2);
        let (t, f) = &all[0];
        assert_eq!((t.as_str(), f.sites[0].pool_user.as_str(), f.collations.clone()), ("web1", "php-a-example-org", vec!["utf8mb4_general_ci".to_string()]));
        assert!(all[1].1.collations.is_empty(), "no database, nothing to compare");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn human_sizes() {
        assert_eq!(human(512), "512.0 B");
        assert_eq!(human(5 * 1024 * 1024), "5.0 MiB");
    }
}
