//! `larry sync` on the source: push each site's files, database dump, certificates and manifest into
//! the target's drop directory. Every step is idempotent: the first run is full, later runs carry
//! only changes (rsync), and the target's `larry target apply` puts it into place.

use larry_config::{MigrationConfig, Site};
use larry_db::{dump, dumpfile, MysqlCli};
use larry_discover::model::Record;
use larry_journal::{Entry, Journal, Outcome};
use larry_target::manifest::{FpmManifest, Manifest, MANIFEST_VERSION};
use larry_target::tls;
use larry_transport::transfer::{rsync_push, rsync_tree, TreeOpts};
use larry_transport::Cmd;
use std::path::{Path, PathBuf};

pub struct Opts {
    pub files: bool,
    pub db: bool,
    pub mirror: bool,
    pub dry_run: bool,
    pub resume: bool,
    pub only: Vec<String>,
}

/// What the target needs to know about one site (validated again on the target).
pub fn build_manifest(cfg: &MigrationConfig, site: &Site, rec: &Record, tls_names: Vec<String>) -> Manifest {
    let f = cfg.resolve_fpm(site);
    Manifest {
        version: MANIFEST_VERSION,
        domain: site.domain.clone(),
        aliases: rec.aliases.clone(),
        docroot: site.docroot_name().to_string(),
        source_vhost_root: rec.vhost_root.clone(),
        source_docroot: rec.docroot.clone(),
        db: site.db.clone(),
        rewrite_paths: site.rewrite_paths,
        manage_pool: site.manage_pool,
        php: rec.php_mode == "fpm" || rec.php_mode == "mod_php",
        tls: tls_names,
        fpm: FpmManifest {
            php_version: f.php_version,
            user: f.user,
            group: f.group,
            pm: f.pm,
            max_children: f.max_children,
            process_idle_timeout: f.process_idle_timeout,
            max_requests: f.max_requests,
            php_value: f.php_value,
            php_flag: f.php_flag,
        },
    }
}

fn rel(p: &str, base: &str) -> Option<String> {
    Path::new(p).strip_prefix(base).ok().filter(|r| !r.as_os_str().is_empty()).map(|r| format!("/{}", r.display()))
}

/// The two trees to push: (source dir, destination below the domain, excludes).
pub fn trees(rec: &Record) -> Vec<(PathBuf, &'static str, Vec<String>)> {
    let mut v = vec![];
    let Some(doc) = rec.docroot.as_deref() else { return v };
    v.push((PathBuf::from(doc), "docroot", rec.exclude_paths.iter().filter_map(|p| rel(p, doc)).collect()));
    if let Some(root) = rec.vhost_root.as_deref().filter(|r| *r != doc) {
        let mut ex: Vec<String> = rec.exclude_paths.iter().filter_map(|p| rel(p, root)).collect();
        if let Some(d) = rel(doc, root) {
            ex.push(d);
        }
        v.push((PathBuf::from(root), "extra", ex));
    }
    v
}

fn lineages(rec: &Record) -> Vec<String> {
    let mut v = vec![];
    for f in &rec.conf_files {
        if let Ok(t) = std::fs::read_to_string(f) {
            v.extend(tls::lineages_in(&t));
        }
    }
    v.sort();
    v.dedup();
    v
}

/// Copy the newest certificate files and the renewal config of each lineage into the staging area.
fn stage_tls(letsencrypt: &Path, names: &[String], dir: &Path) -> Result<Vec<String>, Vec<String>> {
    let mut ok = vec![];
    let mut problems = vec![];
    for n in names {
        let res = (|| -> Result<(), String> {
            let files = tls::latest_files(&letsencrypt.join("archive").join(n))?;
            let a = dir.join("tls/archive").join(n);
            std::fs::create_dir_all(&a).map_err(|e| format!("{}: {e}", a.display()))?;
            for (_, src) in files {
                let dst = a.join(src.file_name().unwrap());
                std::fs::copy(&src, &dst).map_err(|e| format!("{}: {e}", src.display()))?;
            }
            let r = letsencrypt.join("renewal").join(format!("{n}.conf"));
            if r.is_file() {
                std::fs::create_dir_all(dir.join("tls/renewal")).map_err(|e| e.to_string())?;
                std::fs::copy(&r, dir.join("tls/renewal").join(format!("{n}.conf"))).map_err(|e| e.to_string())?;
            }
            Ok(())
        })();
        match res {
            Ok(()) => ok.push(n.clone()),
            Err(e) => problems.push(format!("certificate '{n}': {e}")),
        }
    }
    if problems.is_empty() {
        Ok(ok)
    } else {
        Err(problems)
    }
}

fn hostname() -> String {
    Cmd::new("hostname").run().ok().map(|o| o.stdout.trim().to_string()).filter(|h| !h.is_empty()).unwrap_or_else(|| "source".into())
}

pub fn run(cfg: &MigrationConfig, dir: &Path, o: &Opts) -> Result<u8, String> {
    let sites_path = dir.join("sites.toml");
    let sites = larry_config::SitesFile::load(&sites_path, cfg).map_err(|e| e.to_string())?;
    let records = larry_discover::read_inventory(&dir.join("inventory.jsonl"))?;
    let plan_hash = larry_journal::plan_hash(&std::fs::read(&sites_path).map_err(|e| format!("{}: {e}", sites_path.display()))?);
    let mut journal = Journal::open(&dir.join("journal.jsonl")).map_err(|e| e.to_string())?;
    if o.resume {
        journal.check_resume(&plan_hash).map_err(|e| e.to_string())?;
    }
    let staging = PathBuf::from(&cfg.source.staging_dir);
    larry_transport::ensure_private_dir(&staging)?;
    let ssh_cfg = cfg.ssh.config_file.clone();
    let sql = if o.db && !o.dry_run { Some(MysqlCli::new(cfg.source.db_defaults_file.clone().into())?) } else { None };
    let (mut failed, mut warned) = (0, 0);

    for site in sites.site.iter().filter(|s| o.only.is_empty() || o.only.contains(&s.domain)) {
        let d = &site.domain;
        let target = site.target.clone().or_else(|| cfg.default_target().map(String::from)).ok_or_else(|| format!("{d}: no target"))?;
        let say = |l: &str| println!("[{d}] {l}");
        let step = |name: &str, journal: &mut Journal, f: &mut dyn FnMut() -> Result<(), String>| -> bool {
            if o.resume && journal.is_done(d, &target, name, &plan_hash) {
                say(&format!("{name}: already done under this plan (--resume)"));
                return true;
            }
            let r = f();
            let mut e = Entry::new(d, &target, name, &plan_hash, if r.is_ok() { Outcome::Ok } else { Outcome::Failed });
            e.message = r.as_ref().err().cloned();
            if !o.dry_run {
                let _ = journal.append(e);
            }
            match r {
                Ok(()) => true,
                Err(e) => {
                    say(&format!("FAILED {name}: {e}"));
                    false
                }
            }
        };
        let Some(rec) = records.iter().find(|r| &r.domain == d) else {
            say("FAILED: not in inventory.jsonl; run `larry discover` again");
            failed += 1;
            continue;
        };
        if let Some(why) = &rec.skip {
            say(&format!("skipped: {why}"));
            continue;
        }
        let _lock = if o.dry_run { None } else { Some(crate::target::lock_site(&staging, d)?) };
        let work = staging.join(d);
        let mut site_failed = false;

        // certificates and manifest first: `larry provision` needs them before the first apply
        if o.files {
            let names = lineages(rec);
            let mut tls_ok = names.clone();
            if !o.dry_run && !names.is_empty() {
                let _ = std::fs::remove_dir_all(&work);
                larry_transport::ensure_private_dir(&work)?;
                match stage_tls(Path::new("/etc/letsencrypt"), &names, &work) {
                    Ok(v) => tls_ok = v,
                    Err(problems) => {
                        for p in problems {
                            say(&format!("WARN: {p}; the site will be HTTP-only on the target until it is fixed"));
                            warned += 1;
                        }
                        tls_ok = names.iter().filter(|n| work.join("tls/archive").join(n).is_dir()).cloned().collect();
                    }
                }
            } else if !o.dry_run {
                let _ = std::fs::remove_dir_all(&work);
                larry_transport::ensure_private_dir(&work)?;
            }
            let m = build_manifest(cfg, site, rec, tls_ok);
            if !step("manifest", &mut journal, &mut || {
                if o.dry_run {
                    say(&format!(
                        "would push manifest.json{}",
                        if m.tls.is_empty() { String::new() } else { format!(" and certificate(s) {}", m.tls.join(", ")) }
                    ));
                    return Ok(());
                }
                std::fs::write(work.join("manifest.json"), serde_json::to_string_pretty(&m).map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
                let c = rsync_tree(&ssh_cfg, &target, &work, &format!("./{d}"), &TreeOpts::default())?;
                c.run_checked().map_err(|e| e.to_string())?;
                say("manifest and certificates pushed");
                Ok(())
            }) {
                site_failed = true;
            } else {
                for (src, name, excludes) in trees(rec) {
                    let sname = format!("files:{name}");
                    if !step(&sname, &mut journal, &mut || {
                        let c = rsync_tree(
                            &ssh_cfg,
                            &target,
                            &src,
                            &format!("./{d}/{name}"),
                            &TreeOpts { excludes: &excludes, delete: o.mirror, dry_run: o.dry_run },
                        )?;
                        if o.dry_run {
                            say(&format!("would run {}", c.display()));
                            return Ok(());
                        }
                        c.run_checked().map_err(|e| e.to_string())?;
                        say(&format!("{name} pushed from {}", src.display()));
                        Ok(())
                    }) {
                        site_failed = true;
                        break;
                    }
                }
            }
        }

        if o.db && !site_failed {
            match &site.db {
                None => say("no database for this site"),
                Some(db) => {
                    if !step("db", &mut journal, &mut || {
                        let Some(sql) = &sql else {
                            say(&format!("would dump '{db}' (mode chosen per table engines), verify it and push it with its checksum"));
                            return Ok(());
                        };
                        larry_transport::ensure_private_dir(&work)?;
                        let r = dump::dump_database(sql, d, db, &hostname(), &work, larry_db::now())?;
                        say(&format!("dumped '{db}' ({} bytes, {})", r.bytes, r.mode.flag()));
                        if let Some(old) =
                            rec.docroot.as_deref().filter(|old| Path::new(old) != Path::new(&format!("{}/{d}/{}", cfg.layout.vhost_base, site.docroot_name())))
                        {
                            let n = dumpfile::count_occurrences(&r.path, old)?;
                            if n > 0 {
                                say(&format!("WARN: the dump mentions the old path {old} {n} time(s); database hits are report-only in v1"));
                                warned += 1;
                            }
                        }
                        let side = dumpfile::sidecar(&r.path);
                        let c = rsync_push(&ssh_cfg, &target, &[r.path.as_path(), side.as_path()], &format!("./{d}/"))?;
                        c.run_checked().map_err(|e| e.to_string())?;
                        say("database dump and checksum pushed");
                        Ok(())
                    }) {
                        site_failed = true;
                    }
                }
            }
        }
        if site_failed {
            failed += 1;
        }
    }
    println!("\nsync{}: {failed} site(s) failed, {warned} warning(s)", if o.dry_run { " (dry run)" } else { "" });
    Ok(if failed > 0 {
        1
    } else if warned > 0 {
        2
    } else {
        0
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec() -> Record {
        let mut r = Record::new("shop.example.org");
        r.docroot = Some("/var/www/shop/httpdocs".into());
        r.vhost_root = Some("/var/www/shop".into());
        r.exclude_paths = vec!["/var/www/shop/httpdocs/blog".into(), "/var/www/shop/sub".into()];
        r.php_mode = "fpm".into();
        r.aliases = vec!["www.shop.example.org".into()];
        r
    }

    #[test]
    fn nested_trees_are_excluded_relative_to_each_pushed_tree() {
        let t = trees(&rec());
        assert_eq!(t[0].1, "docroot");
        assert_eq!(t[0].2, vec!["/blog"]);
        assert_eq!(t[1].1, "extra");
        assert_eq!(t[1].2, vec!["/httpdocs/blog", "/sub", "/httpdocs"]);
        let mut flat = rec();
        flat.vhost_root = flat.docroot.clone();
        assert_eq!(trees(&flat).len(), 1, "no extra tree when the docroot is the vhost root");
        let mut none = rec();
        none.docroot = None;
        assert!(trees(&none).is_empty());
    }

    #[test]
    fn manifest_carries_the_resolved_pool_and_validates() {
        let cfg = MigrationConfig::parse(
            "version = 1\n[source]\ndb_defaults_file = \"/x\"\n[ssh]\nconfig_file = \"/c\"\nknown_hosts = \"/k\"\n[targets.web1]\nhost = \"h\"\nhost_key = \"SHA256:abc\"\ntransfer_user = \"migrate\"\nincoming_dir = \"/srv/in\"\ndefault = true\n",
        )
        .unwrap();
        let sites =
            larry_config::SitesFile::parse("[[site]]\ndomain = \"shop.example.org\"\ndocroot = \"public\"\ndb = \"shop\"\nrewrite_paths = true\n", &cfg)
                .unwrap();
        let m = build_manifest(&cfg, &sites.site[0], &rec(), vec![]);
        m.validate().unwrap();
        assert!(m.php && m.rewrite_paths && m.db.as_deref() == Some("shop"));
        assert_eq!(m.fpm.user, "php-shop-example-org");
        assert_eq!(m.source_docroot.as_deref(), Some("/var/www/shop/httpdocs"));
    }

    #[test]
    fn certificates_are_staged_with_the_renewal_config() {
        let d = std::env::temp_dir().join(format!("larry-stage-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        let (le, out) = (d.join("le"), d.join("out"));
        std::fs::create_dir_all(le.join("archive/a.example.org")).unwrap();
        std::fs::create_dir_all(le.join("renewal")).unwrap();
        std::fs::create_dir_all(&out).unwrap();
        for k in ["cert", "chain", "fullchain", "privkey"] {
            std::fs::write(le.join(format!("archive/a.example.org/{k}1.pem")), k).unwrap();
        }
        std::fs::write(le.join("renewal/a.example.org.conf"), "x").unwrap();
        let ok = stage_tls(&le, &["a.example.org".into()], &out).unwrap();
        assert_eq!(ok, vec!["a.example.org"]);
        assert!(out.join("tls/archive/a.example.org/privkey1.pem").is_file() && out.join("tls/renewal/a.example.org.conf").is_file());
        let err = stage_tls(&le, &["missing.example.org".into()], &out).unwrap_err();
        assert!(err[0].contains("missing.example.org"));
        let _ = std::fs::remove_dir_all(&d);
    }
}
