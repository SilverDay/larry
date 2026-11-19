//! `larry preflight` (source) and `larry target preflight` (target, root).
//! Read-only: reports what would stop a migration before anything is copied.

use larry_config::MigrationConfig;
use larry_db::{MysqlCli, Sql};
use larry_transport::ssh;
use larry_transport::transfer::{check_tools, rsync_probe, ToolSpec, ToolStatus, SOURCE_TOOLS, TARGET_TOOLS};
use std::path::Path;

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

/// Source side: tools, config and secret files, pinned host keys, database access, reachability.
pub fn source(cfg: &MigrationConfig) -> Report {
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
        if Path::new(p).is_file() { r.ok("file", p) } else { r.fail("file", &format!("{p} is missing (run `larry init`)")) }
    }
    let known = std::fs::read_to_string(&cfg.ssh.known_hosts).unwrap_or_default();
    let probe_dir = std::env::temp_dir().join(format!("larry-probe-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&probe_dir);
    for (name, t) in &cfg.targets {
        let addr = t.address.as_deref().unwrap_or(&t.host);
        // the pinned key must be the one `migration.toml` says the admin confirmed
        match known.lines().find(|l| l.split_whitespace().next() == Some(addr)) {
            None => r.fail(&format!("host key {name}"), &format!("no pinned key for {addr} in {}", cfg.ssh.known_hosts)),
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
    r
}

/// Target side, run by an admin as root: tools, requested PHP-FPM versions, free space.
pub fn target(php_versions: &[String], vhost_base: &Path, incoming: &Path) -> Report {
    let mut r = Report::new();
    tools(&mut r, TARGET_TOOLS);
    for v in php_versions {
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
    r
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
        let r = target(&["99.9".into(), "x;y".into()], Path::new("/definitely/not/here"), Path::new("/tmp"));
        assert!(r.failed);
        let t = r.text();
        assert!(t.contains("FAIL  php-fpm 99.9") && t.contains("FAIL  php-fpm: 'x;y'") && t.contains("FAIL  vhost base"));
        assert!(t.contains("ok    drop directory") && t.contains("free in /tmp"));
    }

    #[test]
    fn human_sizes() {
        assert_eq!(human(512), "512.0 B");
        assert_eq!(human(5 * 1024 * 1024), "5.0 MiB");
    }
}
