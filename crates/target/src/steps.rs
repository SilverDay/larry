//! A plan is a list of steps. `--dry-run` prints them; a real run executes them in order and stops
//! at the first failure of a step that matters (a failed check or `warn` step only reports).

use crate::tls;
use larry_transport::Cmd;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub enum Step {
    Note(String),
    Mkdir { path: PathBuf, mode: u32 },
    /// Write a file. An existing, different file is renamed with the timestamp, never overwritten.
    /// With `test`, the command runs on the result; if it fails the old file is put back and the step fails.
    Write { path: PathBuf, content: String, mode: u32, test: Option<Cmd> },
    Run { desc: String, cmd: Cmd },
    /// Like `Run`, but a failure is only reported.
    Warn { desc: String, cmd: Cmd },
    /// Rewrite old absolute paths in PHP files below `root` (see `rewrite`); backups go to `backup_dir`.
    Rewrite { root: PathBuf, pairs: Vec<(String, String)>, backup_dir: PathBuf },
    /// Install a certificate lineage from the package into `letsencrypt` (skipped if it already exists).
    Tls { name: String, from: PathBuf, letsencrypt: PathBuf },
}

impl Step {
    pub fn describe(&self) -> String {
        match self {
            Step::Note(s) => format!("note: {s}"),
            Step::Mkdir { path, mode } => format!("mkdir -p {} (mode {mode:04o})", path.display()),
            Step::Write { path, mode, test, .. } => format!(
                "write {} (mode {mode:04o}; an existing different file is renamed with a timestamp){}",
                path.display(),
                test.as_ref().map(|t| format!("; then {}", t.display())).unwrap_or_default()
            ),
            Step::Run { desc, cmd } | Step::Warn { desc, cmd } => format!("{desc}: {}", cmd.display()),
            Step::Rewrite { root, pairs, .. } => format!(
                "rewrite {} in PHP files below {}",
                pairs.iter().map(|(o, n)| format!("{o} -> {n}")).collect::<Vec<_>>().join(", "),
                root.display()
            ),
            Step::Tls { name, letsencrypt, .. } => format!("install certificate '{name}' into {}", letsencrypt.display()),
        }
    }
}

/// Execute (or, with `dry_run`, only print) the steps. `log` receives one line per step.
pub fn execute(steps: &[Step], dry_run: bool, stamp: &str, log: &mut dyn FnMut(String)) -> Result<(), String> {
    for s in steps {
        if dry_run {
            log(format!("would {}", s.describe()));
            if let Step::Rewrite { root, pairs, backup_dir } = s {
                if root.is_dir() {
                    report_rewrite(&crate::rewrite::rewrite_tree(root, pairs, backup_dir, true)?, true, log);
                }
            }
            continue;
        }
        match s {
            Step::Note(n) => log(n.clone()),
            Step::Mkdir { path, mode } => {
                std::fs::create_dir_all(path).map_err(|e| format!("{}: {e}", path.display()))?;
                std::fs::set_permissions(path, std::fs::Permissions::from_mode(*mode)).map_err(|e| format!("{}: {e}", path.display()))?;
            }
            Step::Write { path, content, mode, test } => write_file(path, content, *mode, test.as_ref(), stamp, log)?,
            Step::Run { desc, cmd } => {
                cmd.run_checked().map_err(|e| format!("{desc}: {e}"))?;
                log(format!("done: {desc}"));
            }
            Step::Warn { desc, cmd } => match cmd.run() {
                Ok(o) if o.success() => log(format!("ok: {desc}")),
                Ok(o) => log(format!("WARN: {desc}: {}", o.stderr.trim())),
                Err(e) => log(format!("WARN: {desc}: {e}")),
            },
            Step::Rewrite { root, pairs, backup_dir } => {
                report_rewrite(&crate::rewrite::rewrite_tree(root, pairs, backup_dir, false)?, false, log);
            }
            Step::Tls { name, from, letsencrypt } => install_tls(name, from, letsencrypt, log)?,
        }
    }
    Ok(())
}

fn report_rewrite(r: &crate::rewrite::TreeReport, dry: bool, log: &mut dyn FnMut(String)) {
    let verb = if dry { "would change" } else { "changed" };
    for (f, rw) in &r.changed {
        log(format!("{verb} {} ({} replacement(s))", f.display(), rw.replaced));
        for (n, old, new) in rw.changes.iter().take(5) {
            log(format!("    {n}: - {}\n    {n}: + {}", old.trim(), new.trim()));
        }
    }
    for (f, n) in &r.skipped {
        log(format!("WARN: {n} hit(s) inside PHP serialized strings left alone in {}; fix by hand", f.display()));
    }
    for f in &r.unreadable {
        log(format!("WARN: {} not searched (not UTF-8 or too large)", f.display()));
    }
    if r.changed.is_empty() && r.skipped.is_empty() {
        log("no old paths found in PHP files".into());
    }
}

fn write_file(path: &Path, content: &str, mode: u32, test: Option<&Cmd>, stamp: &str, log: &mut dyn FnMut(String)) -> Result<(), String> {
    let existing = std::fs::read_to_string(path).ok();
    if existing.as_deref() == Some(content) {
        log(format!("unchanged: {}", path.display()));
        return Ok(());
    }
    let err = |e: std::io::Error| format!("{}: {e}", path.display());
    let moved = if path.exists() {
        let mut name = path.file_name().unwrap().to_os_string();
        name.push(format!(".{stamp}.bak"));
        let to = path.with_file_name(name);
        std::fs::rename(path, &to).map_err(err)?;
        log(format!("kept previous file as {}", to.display()));
        Some(to)
    } else {
        None
    };
    let part = path.with_file_name(format!(".{}.larry-part", path.file_name().unwrap().to_string_lossy()));
    std::fs::write(&part, content).map_err(err)?;
    std::fs::set_permissions(&part, std::fs::Permissions::from_mode(mode)).map_err(err)?;
    std::fs::rename(&part, path).map_err(err)?;
    if let Some(t) = test {
        let ok = t.run().map(|o| o.success()).unwrap_or(false);
        if !ok {
            let detail = t.run().map(|o| o.stderr).unwrap_or_default();
            let _ = std::fs::remove_file(path);
            if let Some(old) = &moved {
                let _ = std::fs::rename(old, path);
            }
            return Err(format!("{}: `{}` failed, change reverted: {}", path.display(), t.display(), detail.trim()));
        }
    }
    log(format!("wrote {}", path.display()));
    Ok(())
}

fn install_tls(name: &str, from: &Path, le: &Path, log: &mut dyn FnMut(String)) -> Result<(), String> {
    let live = le.join("live").join(name);
    if live.exists() {
        log(format!("certificate '{name}' is already installed; left alone"));
        return Ok(());
    }
    let src_archive = from.join("archive").join(name);
    let files = tls::latest_files(&src_archive)?;
    let dst_archive = le.join("archive").join(name);
    let e = |p: &Path, e: std::io::Error| format!("{}: {e}", p.display());
    for d in [le.join("archive"), le.join("live"), le.join("renewal")] {
        if !d.exists() {
            std::fs::create_dir_all(&d).map_err(|x| e(&d, x))?;
            std::fs::set_permissions(&d, std::fs::Permissions::from_mode(if d.ends_with("renewal") { 0o755 } else { 0o700 })).map_err(|x| e(&d, x))?;
        }
    }
    std::fs::create_dir_all(&dst_archive).map_err(|x| e(&dst_archive, x))?;
    std::fs::create_dir_all(&live).map_err(|x| e(&live, x))?;
    for (kind, src) in &files {
        let meta = std::fs::symlink_metadata(src).map_err(|x| e(src, x))?;
        if !meta.is_file() {
            return Err(format!("{}: not a regular file", src.display()));
        }
        let fname = src.file_name().unwrap();
        let dst = dst_archive.join(fname);
        std::fs::copy(src, &dst).map_err(|x| e(&dst, x))?;
        let mode = if kind == "privkey.pem" { 0o600 } else { 0o644 };
        std::fs::set_permissions(&dst, std::fs::Permissions::from_mode(mode)).map_err(|x| e(&dst, x))?;
        let link = live.join(kind);
        std::os::unix::fs::symlink(Path::new("../../archive").join(name).join(fname), &link).map_err(|x| e(&link, x))?;
    }
    let renewal_src = from.join("renewal").join(format!("{name}.conf"));
    let renewal_dst = le.join("renewal").join(format!("{name}.conf"));
    if renewal_src.is_file() && !renewal_dst.exists() {
        std::fs::copy(&renewal_src, &renewal_dst).map_err(|x| e(&renewal_dst, x))?;
        std::fs::set_permissions(&renewal_dst, std::fs::Permissions::from_mode(0o644)).map_err(|x| e(&renewal_dst, x))?;
    } else if !renewal_src.is_file() {
        log(format!("WARN: no renewal config for '{name}' in the package; certbot will not renew it here"));
    }
    log(format!("installed certificate '{name}' (key 0600)"));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("larry-steps-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn dry_run_prints_and_changes_nothing() {
        let d = tmp("dry");
        let steps = vec![Step::Mkdir { path: d.join("x"), mode: 0o750 }, Step::Run { desc: "reload".into(), cmd: Cmd::new("false") }];
        let mut lines = vec![];
        execute(&steps, true, "t", &mut |l| lines.push(l)).unwrap();
        assert!(lines[0].starts_with("would mkdir -p") && lines[1].contains("false") && !d.join("x").exists());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn existing_file_is_renamed_and_a_failed_test_restores_it() {
        let d = tmp("write");
        let f = d.join("a.conf");
        std::fs::write(&f, "old").unwrap();
        let mut log = vec![];
        let w = |content: &str, test: Option<Cmd>| Step::Write { path: f.clone(), content: content.into(), mode: 0o644, test };
        execute(&[w("new", Some(Cmd::new("true")))], false, "S1", &mut |l| log.push(l)).unwrap();
        assert_eq!(std::fs::read_to_string(&f).unwrap(), "new");
        assert_eq!(std::fs::read_to_string(d.join("a.conf.S1.bak")).unwrap(), "old");
        let r = execute(&[w("bad", Some(Cmd::new("false")))], false, "S2", &mut |_| {});
        assert!(r.unwrap_err().contains("reverted"));
        assert_eq!(std::fs::read_to_string(&f).unwrap(), "new", "the working file is back");
        // identical content: nothing to do, nothing renamed
        execute(&[w("new", None)], false, "S3", &mut |l| log.push(l)).unwrap();
        assert!(!d.join("a.conf.S3.bak").exists());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn certificate_is_installed_once_with_a_private_key() {
        let d = tmp("tls");
        let (from, le) = (d.join("pkg"), d.join("le"));
        std::fs::create_dir_all(from.join("archive/a.example.org")).unwrap();
        std::fs::create_dir_all(from.join("renewal")).unwrap();
        for k in ["cert", "chain", "fullchain", "privkey"] {
            std::fs::write(from.join(format!("archive/a.example.org/{k}3.pem")), k).unwrap();
        }
        std::fs::write(from.join("renewal/a.example.org.conf"), "# renewal").unwrap();
        let step = Step::Tls { name: "a.example.org".into(), from: from.clone(), letsencrypt: le.clone() };
        let mut log = vec![];
        execute(std::slice::from_ref(&step), false, "t", &mut |l| log.push(l)).unwrap();
        assert_eq!(std::fs::read_to_string(le.join("live/a.example.org/fullchain.pem")).unwrap(), "fullchain");
        let mode = std::fs::metadata(le.join("archive/a.example.org/privkey3.pem")).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        assert!(le.join("renewal/a.example.org.conf").is_file());
        execute(&[step], false, "t", &mut |l| log.push(l)).unwrap();
        assert!(log.last().unwrap().contains("already installed"));
        let _ = std::fs::remove_dir_all(&d);
    }
}
