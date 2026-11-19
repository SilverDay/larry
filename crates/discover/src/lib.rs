//! larry-discover: read-only source discovery (see docs/spec.md, Source discovery).
//!
//! Reports everything that needs a human decision and never guesses.
//! Exit status: 0 clean, 2 review needed, 1 error.
//!
//! Not yet covered: non-InnoDB tables and DEFINER accounts (db stage), how a site sends mail.

macro_rules! re {
    ($p:expr) => {{
        static R: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
        R.get_or_init(|| regex::Regex::new($p).expect("static regex compiles"))
    }};
}

pub mod apache;
pub mod dbdetect;
pub mod model;
pub mod scan;

pub use model::*;

use larry_transport::Cmd;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

/// Everything read from the live system, so the build step can be tested on fixtures.
pub struct Env {
    pub apache_s: String,
    /// `apache2ctl -M` output.
    pub modules: String,
    pub hostnames: BTreeSet<String>,
    /// `None` with `--no-db-check`.
    pub databases: Option<BTreeSet<String>>,
    pub group_file: PathBuf,
    pub cron_files: Vec<PathBuf>,
}

pub struct Options {
    pub vhost_base: String,
    pub max_depth: usize,
}

impl Env {
    /// Read the system: `apache2ctl -S`/`-M`, the database list (read-only account), cron files.
    pub fn collect(db_defaults_file: Option<&Path>) -> Result<Env, String> {
        let apache_s = apache2ctl("-S")?;
        if apache_s.trim().is_empty() {
            return Err("apache2ctl -S produced no output".into());
        }
        let modules = apache2ctl("-M").unwrap_or_default();
        let databases = match db_defaults_file {
            None => None,
            Some(f) => {
                let out = Cmd::new("mysql")
                    .arg(format!("--defaults-extra-file={}", f.display()))
                    .args(["-N", "-B", "-e", "SHOW DATABASES"])
                    .run_checked()
                    .map_err(|e| format!("SHOW DATABASES failed: {e}"))?;
                Some(out.stdout.split_whitespace().filter(|d| !dbdetect::SYSTEM_DBS.contains(d)).map(String::from).collect())
            }
        };
        let hostname = fs::read_to_string("/proc/sys/kernel/hostname").unwrap_or_default().trim().to_string();
        let mut cron_files = vec![PathBuf::from("/etc/crontab")];
        for dir in ["/etc/cron.d", "/var/spool/cron/crontabs"] {
            if let Ok(rd) = fs::read_dir(dir) {
                cron_files.extend(rd.flatten().map(|e| e.path()));
            }
        }
        Ok(Env {
            apache_s,
            modules,
            hostnames: [hostname].into_iter().filter(|h| !h.is_empty()).collect(),
            databases,
            group_file: PathBuf::from("/etc/group"),
            cron_files,
        })
    }
}

fn apache2ctl(flag: &str) -> Result<String, String> {
    // Some Apache builds print the vhost map on stderr, and exit non-zero on warnings.
    let out = Cmd::new("apache2ctl").arg(flag).run().map_err(|e| e.to_string())?;
    Ok(if out.stdout.trim().is_empty() { out.stderr } else { out.stdout })
}

fn norm(p: &str) -> PathBuf {
    Path::new(p).components().collect()
}

struct Raw {
    rec: Record,
    candidates: Vec<PathBuf>,
}

/// Build one record per vhost, sorted by domain.
pub fn build_inventory(env: &Env, opts: &Options) -> Vec<Record> {
    let entries = apache::parse_apache_s(&env.apache_s);
    let known_gids = scan::known_gids(&env.group_file);
    let base = opts.vhost_base.trim_end_matches('/').to_string();
    let has_mod_php = re!(r"(?i)php[0-9_]*_module").is_match(&env.modules);

    // 1. vhosts, from their own <VirtualHost> blocks
    let mut raws: Vec<Raw> = Vec::new();
    for e in &entries {
        let mut rec = Record::new(&e.name);
        rec.aliases = e.aliases.clone();
        let mut docroots: Vec<PathBuf> = vec![];
        let mut socks: Vec<String> = vec![];
        let mut php: Vec<PhpSetting> = vec![];
        for c in &e.confs {
            let real = fs::canonicalize(&c.path).map(|p| p.display().to_string()).unwrap_or_else(|_| c.path.clone());
            if !rec.conf_files.contains(&real) {
                rec.conf_files.push(real.clone());
            }
            let text = match fs::read(&real) {
                Ok(b) => String::from_utf8_lossy(&b).into_owned(),
                Err(err) => {
                    rec.add(Level::Review, "conf-unreadable", format!("cannot read {real}: {err}"));
                    continue;
                }
            };
            let info = apache::parse_conf(&apache::vhost_block(&text, c.line));
            for d in info.docroots {
                let d = norm(&d);
                if !docroots.contains(&d) {
                    docroots.push(d);
                }
            }
            rec.ssl |= info.ssl;
            socks.extend(info.proxy_sockets);
            for (kind, name, value) in info.php {
                php.push(PhpSetting { kind, name, value, source: real.clone() });
            }
        }
        rec.docroots = docroots.iter().map(|d| d.display().to_string()).collect();
        rec.fpm_socket = socks.first().cloned();
        rec.php_settings = php;
        raws.push(Raw { rec, candidates: docroots });
    }

    // 2. which docroot, and whether the vhost is migratable at all
    for r in &mut raws {
        let rec = &mut r.rec;
        let confs: Vec<&str> = rec.conf_files.iter().filter_map(|c| Path::new(c).file_name()?.to_str()).collect();
        let existing: Vec<&PathBuf> = r.candidates.iter().filter(|d| d.is_dir()).collect();
        if env.hostnames.contains(&rec.domain) || (!confs.is_empty() && confs.iter().all(|c| *c == "000-default.conf" || *c == "default-ssl.conf")) {
            rec.skip = Some("the server's own default vhost".into());
        } else if !larry_config::is_domain(&rec.domain) {
            rec.skip = Some("domain name not usable".into());
            rec.add(Level::Review, "bad-domain", "unusable domain name");
        } else if r.candidates.is_empty() {
            rec.skip = Some("redirect-only vhost (no DocumentRoot): no files are moved".into());
            rec.add(Level::Info, "redirect-only", "no DocumentRoot; the vhost is not recreated by larry");
        } else if existing.is_empty() {
            let c: Vec<_> = r.candidates.iter().map(|d| d.display().to_string()).collect();
            rec.skip = Some(format!("docroot does not exist: {}", c.join(" | ")));
            rec.add(Level::Review, "docroot-missing", format!("docroot does not exist: {}", c.join(" | ")));
        } else if existing.len() > 1 {
            let c: Vec<_> = existing.iter().map(|d| d.display().to_string()).collect();
            rec.skip = Some(format!("vhost files disagree on DocumentRoot: {}", c.join(" | ")));
            rec.add(Level::Review, "docroot-conflict", "conflicting DocumentRoots: fix the vhost config, then discover again");
        } else {
            let root = existing[0].clone();
            let name = root.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
            if !larry_config::is_domain(&name) && !name.chars().all(|c| c.is_ascii_alphanumeric() || "._-".contains(c)) {
                rec.skip = Some(format!("docroot directory name '{name}' is not usable"));
                rec.add(Level::Review, "docroot-name", format!("docroot directory name '{name}' is not usable"));
            } else {
                if r.candidates.len() > 1 {
                    let others: Vec<_> = r.candidates.iter().filter(|c| **c != root).map(|c| c.display().to_string()).collect();
                    rec.add(
                        Level::Info,
                        "docroot-differs",
                        format!("DocumentRoot differs between its vhost files; using {} and ignoring {}", root.display(), others.join(", ")),
                    );
                }
                rec.docroot_exists = true;
                rec.docroot_name = Some(name);
                rec.vhost_root = root.parent().map(|p| p.display().to_string());
                rec.docroot = Some(root.display().to_string());
            }
        }
    }

    // 3. nested roots: a vhost inside another vhost's tree becomes its own flat vhost,
    //    and the parent's copy excludes it. Candidate docroots of ALL vhosts count.
    let all_roots: Vec<(String, PathBuf, PathBuf)> = raws
        .iter()
        .flat_map(|r| r.candidates.iter().map(|d| (r.rec.domain.clone(), d.clone(), d.parent().map(Path::to_path_buf).unwrap_or_default())))
        .collect();
    let mut nested_pairs: Vec<(String, String, PathBuf, bool)> = vec![]; // (parent, child, path, vdir_inside)
    for r in &raws {
        let (Some(root), Some(vroot)) = (&r.rec.docroot, &r.rec.vhost_root) else { continue };
        let root = norm(root);
        let vroot = norm(vroot);
        for (other, d, vdir) in &all_roots {
            if *other == r.rec.domain {
                continue;
            }
            if vdir.starts_with(&vroot) && *vdir != vroot {
                nested_pairs.push((r.rec.domain.clone(), other.clone(), vdir.clone(), true));
            } else if d.starts_with(&vroot) && *d != vroot && *d != root {
                nested_pairs.push((r.rec.domain.clone(), other.clone(), d.clone(), false));
            }
        }
    }
    for (parent, child, path, vdir_inside) in &nested_pairs {
        let rel_note = format!("nested inside {parent}: becomes its own flat vhost; {parent}'s copy excludes {}", path.display());
        if let Some(c) = raws.iter_mut().find(|r| &r.rec.domain == child) {
            if c.rec.nested_in.is_none() {
                c.rec.nested_in = Some(parent.clone());
            }
            c.rec.add(Level::Info, "nested", rel_note);
            if !vdir_inside {
                c.rec.add(
                    Level::Review,
                    "nested-docroot-in-vhost-dir",
                    format!("docroot sits directly inside {parent}'s vhost directory; decide how its files are split from {parent}"),
                );
            }
        }
        if let Some(p) = raws.iter_mut().find(|r| &r.rec.domain == parent) {
            let s = path.display().to_string();
            if !p.rec.exclude_paths.contains(&s) {
                p.rec.exclude_paths.push(s);
            }
        }
    }

    // 4. per vhost: PHP mode, database, scan, findings
    let cron_lines = read_cron(&env.cron_files);
    for r in &mut raws {
        let rec = &mut r.rec;
        let (Some(root), Some(vroot)) = (rec.docroot.clone(), rec.vhost_root.clone()) else { continue };
        let (root, vroot) = (PathBuf::from(root), PathBuf::from(vroot));
        rec.exclude_paths.sort();
        let excludes: Vec<PathBuf> = rec.exclude_paths.iter().map(PathBuf::from).collect();

        if rec.fpm_socket.is_some() {
            rec.php_mode = "fpm".into();
        } else if has_mod_php {
            rec.php_mode = "mod_php".into();
        } else if !has_php_file(&root, 2) {
            rec.php_mode = "static".into();
        }
        if root.display().to_string().contains("/subdomains/") {
            rec.add(Level::Info, "subdomains-path", "lives under a parent's subdomains/ on the source; becomes its own flat vhost");
        }

        // database
        let prune: BTreeSet<PathBuf> = excludes.iter().cloned().collect();
        let found = dbdetect::find_candidates(&vroot, &prune, opts.max_depth);
        rec.db = dbdetect::resolve(&found, env.databases.as_ref());
        match rec.db.status {
            DbStatus::Unresolved => rec.add(
                Level::Review,
                "db-unresolved",
                format!("{}. Held back: decide with `plan --db {}=NAME` (or an empty NAME for none)", rec.db.note, rec.domain),
            ),
            DbStatus::Resolved if !rec.db.verified => {
                rec.add(Level::Review, "db-unverified", format!("db '{}' not checked against the server", rec.db.name.clone().unwrap_or_default()))
            }
            _ => {}
        }

        // files
        let new_vroot = format!("{base}/{}", rec.domain);
        let old = vroot.display().to_string();
        let needles: Vec<String> = if old != new_vroot { vec![old.clone()] } else { vec![] };
        let sc = scan::scan_site(&vroot, &root, &excludes, &needles);
        rec.size_bytes = sc.bytes;
        rec.file_count = sc.files;
        rec.old_path_hits = sc.old_path_hits.iter().map(|(f, c)| PathHit { file: f.clone(), count: *c }).collect();
        for (kind, name, value, file) in sc.htaccess_php {
            rec.php_settings.push(PhpSetting { kind, name, value, source: file });
        }
        let orphans: Vec<String> = sc.gids.iter().filter(|g| !known_gids.contains(g)).map(|g| g.to_string()).collect();
        if !orphans.is_empty() {
            rec.add(
                Level::Info,
                "orphaned-gids",
                format!("files owned by GID(s) without a group here: {} (ownership is reset on the target)", orphans.join(", ")),
            );
        }
        if !rec.php_settings.is_empty() {
            rec.add(
                Level::Review,
                "php-settings",
                format!(
                    "{} php_value/php_flag/php_admin_* setting(s) return HTTP 500 under PHP-FPM; proposed as pool settings, review them in sites.toml",
                    rec.php_settings.len()
                ),
            );
        }
        if !rec.old_path_hits.is_empty() {
            let total: u64 = rec.old_path_hits.iter().map(|h| h.count).sum();
            rec.add(Level::Review, "old-paths", format!("{} PHP file(s) mention the old path {old} ({total} hits); the target path is {new_vroot}. Set rewrite_paths = true per site to rewrite them", rec.old_path_hits.len()));
        }
        let cron: Vec<&String> = cron_lines.iter().filter(|l| l.contains(&old)).take(5).collect();
        if !cron.is_empty() {
            rec.add(
                Level::Review,
                "cron",
                format!("cron entries point into the site; v1 does not move cron jobs: {}", cron.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(" | ")),
            );
        }
        rec.add(Level::Info, "size", format!("{} files, {} bytes", rec.file_count, rec.size_bytes));
    }

    // 5. cross-vhost checks
    let mut by_root: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut by_db: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for r in raws.iter().filter(|r| r.rec.skip.is_none()) {
        if let Some(d) = &r.rec.docroot {
            by_root.entry(d.clone()).or_default().push(r.rec.domain.clone());
        }
        if let (DbStatus::Resolved, Some(n)) = (r.rec.db.status, &r.rec.db.name) {
            by_db.entry(n.clone()).or_default().push(r.rec.domain.clone());
        }
    }
    for (root, doms) in by_root.iter().filter(|(_, d)| d.len() > 1) {
        for r in raws.iter_mut().filter(|r| doms.contains(&r.rec.domain)) {
            r.rec.add(
                Level::Review,
                "shared-docroot",
                format!(
                    "shares docroot {root} with {}: each would become its own copy; one vhost with ServerAlias is probably what you want",
                    doms.iter().filter(|d| **d != r.rec.domain).cloned().collect::<Vec<_>>().join(", ")
                ),
            );
        }
    }
    for (db, doms) in by_db.iter().filter(|(_, d)| d.len() > 1) {
        for r in raws.iter_mut().filter(|r| doms.contains(&r.rec.domain)) {
            r.rec.add(
                Level::Info,
                "shared-db",
                format!(
                    "database {db} is shared with {}; it is dumped and imported once per site",
                    doms.iter().filter(|d| **d != r.rec.domain).cloned().collect::<Vec<_>>().join(", ")
                ),
            );
        }
    }

    raws.into_iter().map(|r| r.rec).collect()
}

fn has_php_file(dir: &Path, depth: usize) -> bool {
    let Ok(rd) = fs::read_dir(dir) else { return false };
    for e in rd.flatten() {
        let Ok(ft) = e.file_type() else { continue };
        if ft.is_file() && e.path().extension().map(|x| x.eq_ignore_ascii_case("php")).unwrap_or(false) {
            return true;
        }
        if ft.is_dir() && depth > 0 && has_php_file(&e.path(), depth - 1) {
            return true;
        }
    }
    false
}

fn read_cron(files: &[PathBuf]) -> Vec<String> {
    files
        .iter()
        .filter_map(|f| fs::read_to_string(f).ok())
        .flat_map(|t| t.lines().map(|l| l.trim().to_string()).collect::<Vec<_>>())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect()
}

// ---------------------------------------------------------------- inventory.jsonl

/// Write `inventory.jsonl` atomically (`.part`, then rename), mode 0600.
pub fn write_inventory(path: &Path, records: &[Record]) -> Result<(), String> {
    let part = path.with_extension("jsonl.part");
    let mut f = fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&part).map_err(|e| format!("{}: {e}", part.display()))?;
    for r in records {
        let line = serde_json::to_string(r).map_err(|e| e.to_string())?;
        writeln!(f, "{line}").map_err(|e| format!("{}: {e}", part.display()))?;
    }
    f.sync_all().map_err(|e| e.to_string())?;
    fs::rename(&part, path).map_err(|e| format!("{}: {e}", path.display()))
}

pub fn read_inventory(path: &Path) -> Result<Vec<Record>, String> {
    let text = fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    text.lines()
        .enumerate()
        .filter(|(_, l)| !l.trim().is_empty())
        .map(|(i, l)| serde_json::from_str(l.trim_end_matches('\r')).map_err(|e| format!("{}:{}: {e}", path.display(), i + 1)))
        .collect()
}

// ---------------------------------------------------------------- report

/// 0 clean, 2 review needed.
pub fn exit_code(records: &[Record]) -> i32 {
    if records.iter().any(|r| r.needs_review()) {
        2
    } else {
        0
    }
}

pub fn report(records: &[Record]) -> String {
    let mut out = String::new();
    let ready: Vec<_> = records.iter().filter(|r| r.skip.is_none()).collect();
    let held: Vec<_> = ready.iter().filter(|r| r.db.status == DbStatus::Unresolved).collect();
    out += &format!(
        "Discovered {} vhosts: {} to move ({} held back for a database decision), {} skipped\n",
        records.len(),
        ready.len(),
        held.len(),
        records.len() - ready.len()
    );

    let review: Vec<_> = records.iter().flat_map(|r| r.findings.iter().filter(|f| f.level == Level::Review).map(move |f| (&r.domain, f))).collect();
    if !review.is_empty() {
        out += &format!("\nNEEDS REVIEW ({})\n", review.len());
        for (d, f) in &review {
            out += &format!("  {d}: {}\n", f.message);
        }
    }
    let skipped: Vec<_> = records.iter().filter(|r| r.skip.is_some()).collect();
    if !skipped.is_empty() {
        out += &format!("\nSKIPPED ({})\n", skipped.len());
        let w = skipped.iter().map(|r| r.domain.len()).max().unwrap_or(0);
        for r in skipped {
            out += &format!("  {:<w$}  {}\n", r.domain, r.skip.as_deref().unwrap_or(""));
        }
    }
    if !ready.is_empty() {
        out += "\nINCLUDED\n";
        let w = ready.iter().map(|r| r.domain.len()).max().unwrap_or(0);
        for r in ready {
            let db = r.db.name.as_deref().unwrap_or("-");
            out += &format!("  {:<w$}  php: {:<8} db: {:<18} {}\n", r.domain, r.php_mode, db, r.db.note);
            for f in r.findings.iter().filter(|f| f.level == Level::Info && f.code != "size") {
                out += &format!("  {:<w$}     note: {}\n", "", f.message);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("larry-discover-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    fn write(p: &Path, text: &str) {
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, text).unwrap();
    }

    fn vhost(conf: &Path, name: &str, docroot: Option<&Path>) -> String {
        let root = docroot.map(|d| format!("  DocumentRoot {}\n", d.display())).unwrap_or_default();
        write(conf, &format!("<VirtualHost *:80>\n  ServerName {name}\n{root}</VirtualHost>\n"));
        format!("         port 80 namevhost {name} ({}:1)\n", conf.display())
    }

    fn env(apache_s: String, dbs: Option<&[&str]>, root: &Path) -> Env {
        Env {
            apache_s,
            modules: String::new(),
            hostnames: BTreeSet::new(),
            databases: dbs.map(|d| d.iter().map(|s| s.to_string()).collect()),
            group_file: root.join("group"),
            cron_files: vec![root.join("crontab")],
        }
    }

    #[test]
    fn end_to_end_on_a_fixture() {
        let t = tmpdir("e2e");
        let src = t.join("var-www");
        let mut s = String::new();

        // shop: PHP app with a database, a php_value, and an old absolute path
        let shop = src.join("shop.example.org");
        write(&shop.join("httpdocs/wp-config.php"), "<?php\ndefine('DB_NAME', 'shop_db');\ndefine('DB_PASSWORD', 'pw');\n");
        write(&shop.join("httpdocs/.htaccess"), "php_value memory_limit 256M\n");
        write(&shop.join("httpdocs/inc.php"), &format!("<?php require '{}/lib.php';", shop.display()));
        s += &vhost(&t.join("shop.conf"), "shop.example.org", Some(&shop.join("httpdocs")));

        // static site without a database
        let stat = src.join("static.example.org");
        write(&stat.join("public/index.html"), "hi");
        s += &vhost(&t.join("static.conf"), "static.example.org", Some(&stat.join("public")));

        // parent with a nested child vhost; child's wp-config must not leak into the parent
        let parent = src.join("parent.example.org");
        write(&parent.join("public/index.php"), "<?php");
        write(&parent.join("subdomains/kid/public/wp-config.php"), "define('DB_NAME', 'kid_db');");
        s += &vhost(&t.join("parent.conf"), "parent.example.org", Some(&parent.join("public")));
        s += &vhost(&t.join("kid.conf"), "kid.example.org", Some(&parent.join("subdomains/kid/public")));

        // ambiguous database, redirect-only vhost
        let amb = src.join("amb.example.org");
        write(&amb.join("public/wp-config.php"), "define('DB_NAME', 'a_db');");
        write(&amb.join("public/db.php"), "$dbname = 'b_db';");
        s += &vhost(&t.join("amb.conf"), "amb.example.org", Some(&amb.join("public")));
        s += &vhost(&t.join("redir.conf"), "redir.example.org", None);

        let e = env(s, Some(&["shop_db", "kid_db", "a_db", "b_db"]), &t);
        let recs = build_inventory(&e, &Options { vhost_base: "/srv/vhosts".into(), max_depth: 5 });
        let get = |d: &str| recs.iter().find(|r| r.domain == d).unwrap();

        let shop = get("shop.example.org");
        assert_eq!(shop.db.status, DbStatus::Resolved);
        assert_eq!(shop.db.name.as_deref(), Some("shop_db"));
        assert_eq!(shop.docroot_name.as_deref(), Some("httpdocs"));
        assert_eq!(shop.php_settings.len(), 1);
        assert_eq!(shop.php_settings[0].name, "memory_limit");
        assert_eq!(shop.old_path_hits.len(), 1);
        assert!(shop.needs_review());
        assert!(shop.findings.iter().all(|f| !f.message.contains("pw")));

        assert_eq!(get("static.example.org").db.status, DbStatus::Absent);
        assert_eq!(get("static.example.org").php_mode, "static");

        let parent = get("parent.example.org");
        assert_eq!(parent.db.status, DbStatus::Absent, "child's database must not leak into the parent");
        assert_eq!(parent.exclude_paths.len(), 1);
        assert!(parent.exclude_paths[0].ends_with("subdomains/kid"));
        assert_eq!(get("kid.example.org").nested_in.as_deref(), Some("parent.example.org"));
        assert_eq!(get("kid.example.org").db.name.as_deref(), Some("kid_db"));

        assert_eq!(get("amb.example.org").db.status, DbStatus::Unresolved);
        assert!(get("redir.example.org").skip.as_deref().unwrap().contains("redirect-only"));

        assert_eq!(exit_code(&recs), 2);
        let rep = report(&recs);
        assert!(rep.contains("NEEDS REVIEW") && rep.contains("held back"));

        // JSONL round trip, private file
        let inv = t.join("inventory.jsonl");
        write_inventory(&inv, &recs).unwrap();
        assert_eq!(read_inventory(&inv).unwrap(), recs);
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(fs::metadata(&inv).unwrap().permissions().mode() & 0o777, 0o600);
        fs::remove_dir_all(&t).unwrap();
    }

    #[test]
    fn missing_docroot_and_conflicts_are_reported_not_guessed() {
        let t = tmpdir("edge");
        let mut s = vhost(&t.join("gone.conf"), "gone.example.org", Some(&t.join("nope/public")));
        let a = t.join("a/public");
        fs::create_dir_all(&a).unwrap();
        let b = t.join("b/public");
        fs::create_dir_all(&b).unwrap();
        write(
            &t.join("two.conf"),
            &format!("<VirtualHost *:80>\n DocumentRoot {}\n</VirtualHost>\n<VirtualHost *:443>\n DocumentRoot {}\n</VirtualHost>\n", a.display(), b.display()),
        );
        s += &format!(
            "         port 80 namevhost two.example.org ({}:1)\n         port 443 namevhost two.example.org ({}:4)\n",
            t.join("two.conf").display(),
            t.join("two.conf").display()
        );
        let recs = build_inventory(&env(s, None, &t), &Options { vhost_base: "/srv/vhosts".into(), max_depth: 5 });
        for r in &recs {
            assert!(r.skip.is_some(), "{} should be held back", r.domain);
            assert!(r.needs_review());
        }
        fs::remove_dir_all(&t).unwrap();
    }
}
