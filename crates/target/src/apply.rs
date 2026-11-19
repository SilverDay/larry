//! `larry target apply` for one site: verify what arrived in the drop directory, snapshot, copy,
//! rewrite paths (opt-in), set ownership and ACLs, check access. The database step lives in the cli
//! (it needs the db crate and the admin defaults file).

use crate::manifest::Manifest;
use crate::perms::{access_checks, find_pruned, ownership_steps, Ownership};
use crate::provision::{Env, Resolved};
use crate::steps::Step;
use larry_transport::Cmd;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Default)]
pub struct Options {
    /// Allow files owned by another site's pool user (warn instead of refuse).
    pub adopt: bool,
    /// rsync `--delete`, with removed files moved to a timestamped backup directory.
    pub mirror: bool,
    pub stamp: String,
}

fn is_real_dir(p: &Path) -> bool {
    std::fs::symlink_metadata(p).map(|m| m.is_dir()).unwrap_or(false)
}

/// Read and validate `<incoming>/<domain>/manifest.json`. The directory and file must be real
/// (not symlinks), because root reads them.
pub fn read_manifest(env: &Env, domain: &str) -> Result<Manifest, String> {
    let dir = env.package_dir(domain);
    if !is_real_dir(&dir) {
        return Err(format!("{}: no package directory", dir.display()));
    }
    let f = dir.join("manifest.json");
    let meta = std::fs::symlink_metadata(&f).map_err(|e| format!("{}: {e}", f.display()))?;
    if !meta.is_file() || meta.len() > 1 << 20 {
        return Err(format!("{}: not a regular manifest file", f.display()));
    }
    let m = Manifest::parse(&std::fs::read_to_string(&f).map_err(|e| format!("{}: {e}", f.display()))?)?;
    if m.domain != domain {
        return Err(format!("{}: manifest is for '{}'", f.display(), m.domain));
    }
    Ok(m)
}

/// Domains with a package in the drop directory.
pub fn packages(env: &Env) -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir(&env.incoming)
        .map(|rd| rd.flatten().filter(|e| e.path().join("manifest.json").exists()).map(|e| e.file_name().to_string_lossy().to_string()).collect())
        .unwrap_or_default();
    v.sort();
    v
}

/// Owners (by name) of files under `root` that look like another site's pool user (`php-…`).
pub fn foreign_owners(root: &Path, prune: &[PathBuf], pool_user: &str) -> Vec<String> {
    let out = find_pruned(root, prune, &["-printf", "%u\\n"]).run().map(|o| o.stdout).unwrap_or_default();
    let mut v: Vec<String> = out.lines().filter(|u| u.starts_with("php-") && *u != pool_user).map(String::from).collect();
    v.sort();
    v.dedup();
    v
}

fn has_files(root: &Path, prune: &[PathBuf]) -> bool {
    find_pruned(root, prune, &["!", "-type", "d", "-printf", "x", "-quit"]).run().map(|o| !o.stdout.is_empty()).unwrap_or(false)
}

/// Files in the package that will lose an execute bit under the 0640 rule, and links that point
/// outside the tree: both listed in the report.
pub fn report_lists(pkg: &Path) -> (Vec<String>, Vec<String>) {
    let mut exec = vec![];
    let mut links = vec![];
    fn walk(base: &Path, dir: &Path, exec: &mut Vec<String>, links: &mut Vec<String>) {
        let Ok(rd) = std::fs::read_dir(dir) else { return };
        let mut es: Vec<_> = rd.flatten().collect();
        es.sort_by_key(|e| e.file_name());
        for e in es {
            let p = e.path();
            let Ok(meta) = std::fs::symlink_metadata(&p) else { continue };
            let rel = p.strip_prefix(base).unwrap().display().to_string();
            if meta.is_dir() {
                walk(base, &p, exec, links);
            } else if meta.file_type().is_symlink() {
                if let Ok(t) = std::fs::read_link(&p) {
                    let t = t.to_string_lossy().to_string();
                    if t.starts_with('/') || t.contains("../") || t == ".." {
                        links.push(format!("{rel} -> {t}"));
                    }
                }
            } else if meta.is_file() && meta.permissions().mode() & 0o111 != 0 {
                exec.push(rel);
            }
        }
    }
    walk(pkg, pkg, &mut exec, &mut links);
    (exec, links)
}

fn shorten(lines: &[String], what: &str) -> Step {
    let mut s = format!("WARN: {what} ({}):", lines.len());
    for l in lines.iter().take(8) {
        s.push_str(&format!("\n          {l}"));
    }
    if lines.len() > 8 {
        s.push_str(&format!("\n          ... {} more", lines.len() - 8));
    }
    Step::Note(s)
}

/// Absolute paths of other vhosts' trees nested in this site's tree (left alone by apply).
pub fn nested_trees(env: &Env, r: &Resolved, domain: &str) -> Vec<PathBuf> {
    let mut v = vec![];
    let Ok(rd) = std::fs::read_dir(&env.apache_sites) else { return v };
    for e in rd.flatten() {
        let p = e.path();
        if p.extension().is_none_or(|x| x != "conf")
            || e.file_name().to_string_lossy().starts_with(&format!("{domain}."))
            || e.file_name().to_string_lossy().starts_with(&format!("{domain}-"))
        {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(&p) else { continue };
        for d in crate::vhost::docroots_of(&text) {
            let d = std::fs::canonicalize(&d).unwrap_or_else(|_| PathBuf::from(&d));
            if d == r.docroot {
                continue;
            }
            // the nested vhost's tree: its docroot's parent when that is inside ours, else the docroot
            let cand = d.parent().filter(|c| *c != r.vhost_root && *c != r.docroot && c.starts_with(&r.vhost_root)).map(Path::to_path_buf).unwrap_or(d.clone());
            if cand.starts_with(&r.vhost_root) && cand != r.vhost_root {
                v.push(cand);
            }
        }
    }
    v.sort();
    v.dedup();
    v
}

/// Everything `target apply` does to the files of one site, as steps.
pub fn plan_apply(m: &Manifest, env: &Env, r: &Resolved, opts: &Options) -> Result<Vec<Step>, String> {
    let pkg = env.package_dir(&m.domain);
    let (pkg_doc, pkg_extra) = (pkg.join("docroot"), pkg.join("extra"));
    for (p, what) in [(&pkg_doc, "docroot"), (&pkg_extra, "extra")] {
        if std::fs::symlink_metadata(p).is_ok() && !is_real_dir(p) {
            return Err(format!("{}: package {what} is not a plain directory; refusing", p.display()));
        }
    }
    if !r.vhost_root.is_dir() {
        return Err(format!("{}: vhost directory missing; run `larry provision` first", r.vhost_root.display()));
    }
    let nested = nested_trees(env, r, &m.domain);
    let mut v = vec![];

    // guard: another site's files
    let foreign = foreign_owners(&r.vhost_root, &nested, &r.pool_user);
    if !foreign.is_empty() {
        let msg = format!("{} holds files owned by another vhost's pool user: {}", r.vhost_root.display(), foreign.join(", "));
        if !opts.adopt {
            return Err(format!(
                "{msg}. Taking them over would break that vhost and expose its files to {}. Nothing changed; re-run with --adopt if they are stale.",
                r.pool_user
            ));
        }
        v.push(Step::Note(format!("WARN: {msg} (--adopt)")));
    }

    // snapshot before anything is replaced
    if has_files(&r.vhost_root, &nested) {
        let snap = env.backup_dir.join(format!("{}-{}.files.tar.gz", m.domain, opts.stamp));
        v.push(Step::Mkdir { path: env.backup_dir.clone(), mode: 0o700 });
        let mut c = Cmd::new("tar").args(["--acls", "--xattrs", "--anchored"]);
        let name = r.vhost_root.file_name().unwrap().to_string_lossy().to_string();
        for n in &nested {
            c = c.arg(format!("--exclude={name}/{}", n.strip_prefix(&r.vhost_root).unwrap().display()));
        }
        c = c.arg("-czf").arg(&snap).arg("-C").arg(r.vhost_root.parent().unwrap()).arg(&name);
        v.push(Step::Run { desc: format!("snapshot to {}", snap.display()), cmd: c });
    }

    // copy
    let rs = |from: &Path, to: &Path, excludes: Vec<String>| {
        let mut c = Cmd::new("rsync").args(["-a", "--no-owner", "--no-group", "--no-devices", "--no-specials"]);
        if opts.mirror {
            let del = env.backup_dir.join(format!("{}-{}-deleted/{}", m.domain, opts.stamp, to.file_name().unwrap().to_string_lossy()));
            c = c.args(["--delete", "--backup"]).arg(format!("--backup-dir={}", del.display()));
        }
        for e in excludes {
            c = c.arg(format!("--exclude={e}"));
        }
        c.arg(format!("{}/", from.display())).arg(format!("{}/", to.display()))
    };
    if is_real_dir(&pkg_doc) {
        let ex = nested.iter().filter_map(|n| n.strip_prefix(&r.docroot).ok()).map(|p| format!("/{}", p.display())).collect();
        v.push(Step::Run { desc: "copy docroot".into(), cmd: rs(&pkg_doc, &r.docroot, ex) });
    } else {
        v.push(Step::Note("no docroot in the package; nothing to copy".into()));
    }
    if is_real_dir(&pkg_extra) {
        let ex = nested
            .iter()
            .filter_map(|n| n.strip_prefix(&r.vhost_root).ok())
            .map(|p| format!("/{}", p.display()))
            .chain([format!("/{}", r.docroot.file_name().unwrap().to_string_lossy())])
            .collect();
        v.push(Step::Run { desc: "copy the rest of the vhost directory".into(), cmd: rs(&pkg_extra, &r.vhost_root, ex) });
    }

    // report: what the policy changes
    let (exec, links) = report_lists(&pkg);
    if !exec.is_empty() {
        v.push(shorten(&exec, "files that lose their execute bit (0640 policy)"));
    }
    if !links.is_empty() {
        v.push(shorten(&links, "symlinks with absolute or ../ targets; check they still resolve here"));
    }

    // path rewriting, after every sync because each sync brings back the source's copies
    if m.rewrite_paths {
        let mut pairs = vec![];
        if let (Some(old), true) = (&m.source_docroot, true) {
            pairs.push((old.clone(), r.docroot.display().to_string()));
        }
        if let Some(old) = &m.source_vhost_root {
            pairs.push((old.clone(), r.vhost_root.display().to_string()));
        }
        v.push(Step::Rewrite { root: r.vhost_root.clone(), pairs, backup_dir: env.backup_dir.join(format!("{}-{}-rewrite", m.domain, opts.stamp)) });
    }

    // ownership, ACLs, checks
    let o = Ownership {
        vhost_root: &r.vhost_root,
        docroot: &r.docroot,
        pool_user: &r.pool_user,
        web_group: &env.web_group,
        deploy_user: env.deploy_user.as_deref(),
        prune: &nested,
    };
    v.extend(ownership_steps(&o));
    let probe = std::fs::read_dir(&pkg_doc).ok().and_then(|rd| {
        let mut names: Vec<String> =
            rd.flatten().filter(|e| e.file_type().is_ok_and(|t| t.is_file())).map(|e| e.file_name().to_string_lossy().to_string()).collect();
        names.sort();
        names.iter().find(|n| n.starts_with("index.")).or(names.first()).map(|n| r.docroot.join(n))
    });
    v.extend(access_checks(&o, &r.pool_group, probe.as_deref()));
    Ok(v)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::sample;
    use crate::provision::resolve;

    fn setup(tag: &str) -> (Env, PathBuf, Manifest) {
        let d = std::env::temp_dir().join(format!("larry-apply-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        for s in ["vhosts/shop.example.org/public", "sites", "php", "incoming/shop.example.org/docroot", "incoming/shop.example.org/extra"] {
            std::fs::create_dir_all(d.join(s)).unwrap();
        }
        let m = sample();
        std::fs::write(d.join("incoming/shop.example.org/manifest.json"), serde_json::to_string(&m).unwrap()).unwrap();
        std::fs::write(d.join("incoming/shop.example.org/docroot/index.php"), "<?php").unwrap();
        let e = Env {
            vhost_base: d.join("vhosts"),
            apache_sites: d.join("sites"),
            php_etc: d.join("php"),
            letsencrypt: d.join("le"),
            incoming: d.join("incoming"),
            backup_dir: d.join("bak"),
            web_group: "www-data".into(),
            deploy_user: Some("deploy".into()),
        };
        (e, d, m)
    }

    fn text(v: &[Step]) -> String {
        v.iter().map(|s| s.describe()).collect::<Vec<_>>().join("\n")
    }

    #[test]
    fn plan_copies_then_sets_ownership_then_checks() {
        let (e, d, m) = setup("plan");
        let r = resolve(&m, &e, "8.3").unwrap();
        let t = text(&plan_apply(&m, &e, &r, &Options { stamp: "S".into(), ..Default::default() }).unwrap());
        let order = ["copy docroot", "set owner", "set file mode 0640", "deploy user ACL on files", "group ACL on files", "can traverse the docroot"];
        let pos: Vec<usize> = order.iter().map(|k| t.find(k).unwrap_or_else(|| panic!("missing {k}\n{t}"))).collect();
        assert!(pos.windows(2).all(|w| w[0] < w[1]), "{t}");
        assert!(t.contains("rsync -a --no-owner --no-group --no-devices --no-specials"));
        assert!(!t.contains("--delete") && !t.contains("snapshot"), "empty tree: nothing to snapshot, no deletion");
        assert!(read_manifest(&e, "shop.example.org").is_ok());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn existing_files_are_snapshotted_and_mirror_moves_deletions_aside() {
        let (e, d, m) = setup("snap");
        std::fs::write(e.vhost_base.join("shop.example.org/public/old.html"), "x").unwrap();
        let r = resolve(&m, &e, "8.3").unwrap();
        let t = text(&plan_apply(&m, &e, &r, &Options { mirror: true, stamp: "S".into(), ..Default::default() }).unwrap());
        assert!(t.contains("tar --acls --xattrs --anchored -czf") && t.contains("shop.example.org-S.files.tar.gz"));
        assert!(t.contains("--delete --backup --backup-dir=") && t.contains("shop.example.org-S-deleted/public"));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn a_package_that_is_a_symlink_is_refused() {
        let (e, d, m) = setup("link");
        let docroot = d.join("incoming/shop.example.org/docroot");
        std::fs::remove_dir_all(&docroot).unwrap();
        std::os::unix::fs::symlink("/etc", &docroot).unwrap();
        let r = resolve(&m, &e, "8.3").unwrap();
        assert!(plan_apply(&m, &e, &r, &Options::default()).unwrap_err().contains("not a plain directory"));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn nested_vhost_tree_is_left_out_of_the_copy_and_the_ownership_pass() {
        let (e, d, m) = setup("nested");
        let child = e.vhost_base.join("shop.example.org/public/blog");
        std::fs::create_dir_all(&child).unwrap();
        std::fs::write(e.apache_sites.join("blog.example.org.conf"), format!("DocumentRoot {}\n", child.display())).unwrap();
        let r = resolve(&m, &e, "8.3").unwrap();
        let t = text(&plan_apply(&m, &e, &r, &Options { stamp: "S".into(), ..Default::default() }).unwrap());
        assert!(t.contains("--exclude=/blog") && t.contains("'(' -path") && t.contains("public/blog ')' -prune -o"));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn report_lists_find_exec_files_and_outside_links() {
        let d = std::env::temp_dir().join(format!("larry-lists-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join("a")).unwrap();
        std::fs::write(d.join("a/run.sh"), "").unwrap();
        std::fs::set_permissions(d.join("a/run.sh"), std::fs::Permissions::from_mode(0o755)).unwrap();
        std::os::unix::fs::symlink("/etc/passwd", d.join("abs")).unwrap();
        std::os::unix::fs::symlink("inner", d.join("ok")).unwrap();
        let (exec, links) = report_lists(&d);
        assert_eq!(exec, vec!["a/run.sh"]);
        assert_eq!(links, vec!["abs -> /etc/passwd"]);
        let _ = std::fs::remove_dir_all(&d);
    }
}
