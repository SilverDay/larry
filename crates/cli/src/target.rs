//! `larry provision` and `larry target apply`: run on a target server, as root, by an admin.
//! They read what the source pushed into the drop directory (`<incoming>/<domain>/…`), never the
//! source's configuration. One site failing never stops the others.

use larry_db::{checks, dumpfile, import, MysqlCli};
use larry_journal::{Entry, Journal, Outcome};
use larry_target::{apply, appconfig, provision, steps};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct Common {
    pub incoming: PathBuf,
    pub vhost_base: PathBuf,
    pub web_group: String,
    pub deploy_user: Option<String>,
    pub backup_dir: PathBuf,
    pub lock_dir: PathBuf,
    pub dry_run: bool,
    /// Domains to handle; empty means every package in the drop directory.
    pub only: Vec<String>,
}

impl Common {
    fn env(&self) -> provision::Env {
        provision::Env {
            vhost_base: self.vhost_base.clone(),
            apache_sites: "/etc/apache2/sites-available".into(),
            php_etc: "/etc/php".into(),
            letsencrypt: "/etc/letsencrypt".into(),
            incoming: self.incoming.clone(),
            backup_dir: self.backup_dir.clone(),
            web_group: self.web_group.clone(),
            deploy_user: self.deploy_user.clone(),
        }
    }
}

/// The highest PHP version with an FPM pool directory (what the target runs by default).
pub fn default_php(php_etc: &Path) -> Option<String> {
    let mut v: Vec<(u32, u32, String)> = std::fs::read_dir(php_etc)
        .ok()?
        .flatten()
        .filter(|e| e.path().join("fpm/pool.d").is_dir())
        .filter_map(|e| {
            let n = e.file_name().to_string_lossy().to_string();
            let (a, b) = n.split_once('.')?;
            Some((a.parse().ok()?, b.parse().ok()?, n))
        })
        .collect();
    v.sort();
    v.pop().map(|t| t.2)
}

/// One lock per site, held until the guard drops (an advisory flock; a second run fails fast).
#[derive(Debug)]
pub struct SiteLock(#[allow(dead_code)] std::fs::File);

pub fn lock_site(dir: &Path, domain: &str) -> Result<SiteLock, String> {
    std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let p = dir.join(format!("larry-{domain}.lock"));
    let f = std::fs::OpenOptions::new().create(true).write(true).truncate(false).open(&p).map_err(|e| format!("{}: {e}", p.display()))?;
    match f.try_lock() {
        Ok(()) => Ok(SiteLock(f)),
        Err(_) => Err(format!("{domain}: another larry run holds the lock ({})", p.display())),
    }
}

fn sites(c: &Common) -> Result<Vec<String>, String> {
    let env = c.env();
    let all = apply::packages(&env);
    if c.only.is_empty() {
        if all.is_empty() {
            return Err(format!("no packages in {} (run `larry sync` on the source first)", c.incoming.display()));
        }
        return Ok(all);
    }
    for d in &c.only {
        if !all.contains(d) {
            return Err(format!("{d}: no package in {}", c.incoming.display()));
        }
    }
    Ok(c.only.clone())
}

pub fn need_root(dry_run: bool) -> Result<(), String> {
    if dry_run {
        return Ok(());
    }
    let uid = larry_transport::Cmd::new("id").arg("-u").run_checked().map_err(|e| e.to_string())?.stdout;
    if uid.trim() != "0" {
        return Err("this command changes the server and must run as root (use --dry-run to see the plan)".into());
    }
    Ok(())
}

struct Tally {
    failed: usize,
    warned: usize,
}

fn printer<'a>(domain: &'a str, tally: &'a mut Tally) -> impl FnMut(String) + 'a {
    move |l: String| {
        if l.starts_with("WARN") {
            tally.warned += 1;
        }
        println!("[{domain}] {l}");
    }
}

fn journal(c: &Common) -> Option<Journal> {
    if c.dry_run {
        return None;
    }
    larry_transport::ensure_private_dir(&c.backup_dir).ok()?;
    Journal::open(&c.backup_dir.join("journal.jsonl")).ok()
}

fn record(j: &mut Option<Journal>, domain: &str, step: &str, plan_hash: &str, r: &Result<(), String>) {
    if let Some(j) = j {
        let mut e = Entry::new(domain, "this-server", step, plan_hash, if r.is_ok() { Outcome::Ok } else { Outcome::Failed });
        e.message = r.as_ref().err().cloned();
        let _ = j.append(e);
    }
}

pub fn provision(c: &Common) -> Result<u8, String> {
    need_root(c.dry_run)?;
    let env = c.env();
    let domains = sites(c)?;
    let default = default_php(&env.php_etc).unwrap_or_else(|| "8.3".into());
    let stamp = larry_db::stamp(larry_db::now());
    let mut tally = Tally { failed: 0, warned: 0 };
    let mut j = journal(c);
    for d in domains {
        let r = (|| -> Result<(), String> {
            let _lock = if c.dry_run { None } else { Some(lock_site(&c.lock_dir, &d)?) };
            let m = apply::read_manifest(&env, &d)?;
            let res = provision::resolve(&m, &env, &default)?;
            if let Some(a) = &res.adopted {
                println!("[{d}] adopting existing vhost {} (pool user {})", a.conf.display(), res.pool_user);
            }
            let plan = provision::plan_provision(&m, &env, &res)?;
            steps::execute(&plan, c.dry_run, &stamp, &mut printer(&d, &mut tally))
        })();
        record(&mut j, &d, "provision", "-", &r);
        if let Err(e) = r {
            tally.failed += 1;
            println!("[{d}] FAILED: {e}");
        }
    }
    finish("provision", &tally)
}

fn finish(what: &str, t: &Tally) -> Result<u8, String> {
    println!("\n{what}: {} failed, {} warning(s)", t.failed, t.warned);
    Ok(if t.failed > 0 { 1 } else if t.warned > 0 { 2 } else { 0 })
}

pub struct ApplyOpts {
    pub adopt: bool,
    pub mirror: bool,
    pub db_defaults_file: PathBuf,
}

pub fn apply(c: &Common, o: &ApplyOpts) -> Result<u8, String> {
    need_root(c.dry_run)?;
    let env = c.env();
    let domains = sites(c)?;
    let default = default_php(&env.php_etc).unwrap_or_else(|| "8.3".into());
    let now = larry_db::now();
    let stamp = larry_db::stamp(now);
    let mut tally = Tally { failed: 0, warned: 0 };
    let mut j = journal(c);
    for d in domains {
        let r = (|| -> Result<(), String> {
            let _lock = if c.dry_run { None } else { Some(lock_site(&c.lock_dir, &d)?) };
            let m = apply::read_manifest(&env, &d)?;
            let res = provision::resolve(&m, &env, &default)?;
            let plan = apply::plan_apply(&m, &env, &res, &apply::Options { adopt: o.adopt, mirror: o.mirror, stamp: stamp.clone() })?;
            // the database is checked before any file is touched
            let dump = env.package_dir(&d).join(format!("{d}.db.sql.gz"));
            let db_job = match (&m.db, dump.is_file()) {
                (Some(db), true) => Some(db_precheck(&d, db, &dump)?),
                (None, true) => return Err(format!("{d}: a database dump arrived but the manifest names no database")),
                _ => None,
            };
            let mut log = printer(&d, &mut tally);
            steps::execute(&plan, c.dry_run, &stamp, &mut log)?;
            if let Some(db) = db_job {
                apply_db(&d, &db, &dump, &res.vhost_root, c, o, now, &mut log)?;
            }
            Ok(())
        })();
        let h = larry_journal::plan_hash(apply::read_manifest(&env, &d).ok().map(|m| serde_json::to_vec(&m).unwrap_or_default()).unwrap_or_default().as_slice());
        record(&mut j, &d, "apply", &h, &r);
        if let Err(e) = r {
            tally.failed += 1;
            println!("[{d}] FAILED: {e}");
        }
    }
    finish("apply", &tally)
}

/// Before anything changes: checksum, header and USE line must agree with the manifest.
fn db_precheck(domain: &str, db: &str, dump: &Path) -> Result<String, String> {
    dumpfile::verify_checksum(dump).map_err(|e| format!("{}: {e}", dump.display()))?;
    let info = dumpfile::inspect(dump)?;
    let h = info.header.ok_or_else(|| format!("{}: not a larry dump (no header)", dump.display()))?;
    if h.domain != domain || h.db != db {
        return Err(format!("{domain}: the dump is for {}/{}, the manifest says {domain}/{db}", h.domain, h.db));
    }
    Ok(db.to_string())
}

#[allow(clippy::too_many_arguments)]
fn apply_db(domain: &str, db: &str, dump: &Path, vhost_root: &Path, c: &Common, o: &ApplyOpts, now: u64, log: &mut dyn FnMut(String)) -> Result<(), String> {
    larry_config::check_secret_file(&o.db_defaults_file).map_err(|e| format!("{domain}: database admin defaults file: {e}"))?;
    let sql = MysqlCli::new(o.db_defaults_file.clone())?;
    let rep = import::import(&sql, dump, &import::ImportOpts { backup_dir: &c.backup_dir.join("db"), dry_run: c.dry_run, now }).map_err(|e| e.to_string())?;
    if c.dry_run {
        log(format!(
            "would replace database '{db}' ({} table(s) there now{}), dump has {} table(s)",
            rep.tables_before,
            if rep.existed && rep.tables_before > 0 { "; it is dumped to the backup directory first" } else { "" },
            rep.tables_in_dump
        ));
    } else {
        log(format!("database '{db}' replaced: {} table(s){}", rep.tables_after.unwrap_or(0), rep.backup.as_ref().map(|b| format!("; previous copy in {}", b.display())).unwrap_or_default()));
    }
    for w in &rep.warnings {
        log(format!("WARN: {w}"));
    }
    for d in &rep.missing_definers {
        log(format!("WARN: definer {d} does not exist here; views, triggers and routines it owns fail until you create it"));
    }
    // the app's own DB user, from the config it just received
    match appconfig::find(vhost_root, db) {
        None => log(format!("WARN: no supported app config names database '{db}' with credentials; create the app's database user by hand")),
        Some(cr) if !appconfig::is_local_host(&cr.host) => log(format!("WARN: {} points at database host '{}'; no local account was created", cr.source, cr.host.clone().unwrap_or_default())),
        Some(cr) if c.dry_run => log(format!("would ensure database user '{}'@'localhost' (credentials from {}) with rights on '{db}' only", cr.user, cr.source)),
        Some(cr) => match checks::ensure_app_user(&sql, &cr.user, &cr.password, db)? {
            checks::UserOutcome::Created => log(format!("database user '{}'@'localhost' created (credentials from {})", cr.user, cr.source)),
            checks::UserOutcome::Existing => log(format!("database user '{}'@'localhost' already existed; password left alone, rights on '{db}' re-applied", cr.user)),
        },
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_php_is_the_highest_installed() {
        let d = std::env::temp_dir().join(format!("larry-php-{}", std::process::id()));
        for v in ["8.1", "8.3", "8.10", "7.4"] {
            std::fs::create_dir_all(d.join(v).join("fpm/pool.d")).unwrap();
        }
        std::fs::create_dir_all(d.join("9.9/cli")).unwrap();
        assert_eq!(default_php(&d).as_deref(), Some("8.10"));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn a_site_cannot_be_locked_twice() {
        let d = std::env::temp_dir().join(format!("larry-lock-{}", std::process::id()));
        let a = lock_site(&d, "a.example.org").unwrap();
        assert!(lock_site(&d, "a.example.org").unwrap_err().contains("another larry run"));
        assert!(lock_site(&d, "b.example.org").is_ok(), "other sites are not blocked");
        drop(a);
        assert!(lock_site(&d, "a.example.org").is_ok());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn dump_for_another_site_is_refused_before_anything_changes() {
        let d = std::env::temp_dir().join(format!("larry-pre-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        let p = d.join("x.db.sql.gz");
        let mut enc = flate2::write::GzEncoder::new(std::fs::File::create(&p).unwrap(), flate2::Compression::default());
        std::io::Write::write_all(&mut enc, format!("{}\nUSE `other`;\n", larry_db::dumpfile::header_line("a.example.org", "other", "src", "2026-01-01T00:00:00Z")).as_bytes()).unwrap();
        enc.finish().unwrap();
        larry_db::dumpfile::write_sidecar(&p).unwrap();
        assert!(db_precheck("a.example.org", "shop", &p).unwrap_err().contains("manifest says"));
        assert!(db_precheck("a.example.org", "other", &p).is_ok());
        let _ = std::fs::remove_dir_all(&d);
    }
}
