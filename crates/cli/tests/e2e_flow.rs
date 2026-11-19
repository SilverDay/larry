//! The whole data path with the real binary: `larry sync` pushes through a private sshd with the forced
//! rrsync into a drop directory, then `larry target apply` (run under fakeroot, so chown/chmod/setfacl
//! run for real without being root) puts it into a vhost tree. Skipped when sshd, rrsync, rsync or
//! fakeroot are missing.
//!
//! Proves: nested vhost trees stay out of the copy; the old path is rewritten in PHP files only;
//! a second run snapshots what is there first; `--mirror` moves removed files aside instead of deleting.

use larry_transport::ssh::{self, TargetSsh};
use larry_transport::Cmd;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

struct Sshd(Child);
impl Drop for Sshd {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
struct Cleanup(PathBuf);
impl Drop for Cleanup {
    fn drop(&mut self) {
        let cfg = self.0.join("ssh_config");
        if cfg.exists() {
            let _ = Cmd::new("ssh").arg("-F").arg(&cfg).args(["-O", "exit", "larry-web1"]).run();
        }
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn keygen(p: &Path) {
    Cmd::new("ssh-keygen").args(["-q", "-t", "ed25519", "-N", "", "-f"]).arg(p).run_checked().unwrap();
}

fn larry(d: &Path, args: &[&str]) -> (i32, String) {
    let o = Command::new(env!("CARGO_BIN_EXE_larry")).arg("-c").arg(d.join("migration.toml")).args(args).output().unwrap();
    (o.status.code().unwrap_or(-1), format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr)))
}

fn apply(d: &Path, extra: &[&str]) -> (i32, String) {
    let mut c = Command::new("fakeroot");
    c.arg("--").arg(env!("CARGO_BIN_EXE_larry")).args(["target", "apply", "--incoming"]).arg(d.join("incoming"));
    c.arg("--vhost-base").arg(d.join("vhosts")).arg("--backup-dir").arg(d.join("bak")).arg("--lock-dir").arg(d.join("lock"));
    let o = c.args(extra).arg("shop.example.org").output().unwrap();
    (o.status.code().unwrap_or(-1), format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr)))
}

#[test]
fn sync_then_apply_end_to_end() {
    if !Path::new("/usr/sbin/sshd").exists()
        || !Path::new("/usr/bin/rrsync").exists()
        || larry_transport::find_tool(&["rsync"]).is_none()
        || larry_transport::find_tool(&["fakeroot"]).is_none()
    {
        eprintln!("SKIPPED: sshd, rrsync, rsync or fakeroot not installed");
        return;
    }
    let d = PathBuf::from(format!("/tmp/lf-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    let _cleanup = Cleanup(d.clone());
    for s in ["incoming", "stage", "vhosts/shop.example.org/public", "src/shop/httpdocs/blog", "src/shop/logs"] {
        std::fs::create_dir_all(d.join(s)).unwrap();
    }
    let me = Cmd::new("id").arg("-un").run_checked().unwrap().stdout.trim().to_string();
    let my_group = Cmd::new("id").arg("-gn").run_checked().unwrap().stdout.trim().to_string();

    // the source tree
    let src = d.join("src/shop");
    let old = src.join("httpdocs").display().to_string();
    std::fs::write(src.join("httpdocs/index.php"), format!("<?php $root = '{old}'; $v = '{}';", src.display())).unwrap();
    std::fs::write(src.join("httpdocs/page.html"), format!("see {old}")).unwrap();
    std::fs::write(src.join("httpdocs/blog/post.php"), "<?php // nested vhost, not ours").unwrap();
    std::fs::write(src.join("logs/access.log"), "log").unwrap();

    // private sshd, host key pinned the way `init` does it
    keygen(&d.join("hostkey"));
    keygen(&d.join("id_ed25519"));
    let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let pubkey = std::fs::read_to_string(d.join("id_ed25519.pub")).unwrap();
    let ak = ssh::authorized_keys_line(&pubkey, "127.0.0.1", &d.join("incoming").display().to_string(), "/usr/bin/rrsync").unwrap();
    std::fs::write(d.join("authorized_keys"), format!("{ak}\n")).unwrap();
    std::fs::set_permissions(d.join("authorized_keys"), std::os::unix::fs::PermissionsExt::from_mode(0o600)).unwrap();
    std::fs::write(
        d.join("sshd_config"),
        format!("Port {port}\nListenAddress 127.0.0.1\nHostKey {0}/hostkey\nPidFile {0}/sshd.pid\nAuthorizedKeysFile {0}/authorized_keys\nUsePAM no\nPasswordAuthentication no\nStrictModes no\n", d.display()),
    )
    .unwrap();
    let _server =
        Sshd(Command::new("/usr/sbin/sshd").args(["-D", "-e", "-f"]).arg(d.join("sshd_config")).stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap());
    for _ in 0..40 {
        if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    let hostpub = std::fs::read_to_string(d.join("hostkey.pub")).unwrap();
    let fp = ssh::fingerprint(&hostpub).unwrap();
    let pinned = ssh::pin("127.0.0.1", &format!("127.0.0.1 {}", hostpub.trim()), &fp).unwrap();
    let (t, b) = ssh::parse_key(&pinned).unwrap();
    std::fs::write(d.join("known_hosts"), format!("[127.0.0.1]:{port} {t} {b}\n")).unwrap();
    let identity = d.join("id_ed25519").display().to_string();
    let generated = ssh::ssh_config(
        &[TargetSsh { name: "web1", address: "127.0.0.1", user: &me, identity_file: &identity }],
        &d.join("known_hosts").display().to_string(),
        &d.display().to_string(),
    )
    .unwrap();
    std::fs::write(d.join("ssh_config"), format!("Host larry-web1\n    Port {port}\n\n{generated}")).unwrap();

    // config, inventory, plan
    std::fs::write(
        d.join("migration.toml"),
        format!(
            "version = 1\n[source]\ndb_defaults_file = \"/nonexistent\"\nstaging_dir = \"{0}/stage\"\n[ssh]\nconfig_file = \"{0}/ssh_config\"\nknown_hosts = \"{0}/known_hosts\"\n[targets.web1]\nhost = \"127.0.0.1\"\nhost_key = \"{fp}\"\ntransfer_user = \"{me}\"\nincoming_dir = \"{0}/incoming\"\ndefault = true\n[layout]\nvhost_base = \"{0}/vhosts\"\n",
            d.display()
        ),
    )
    .unwrap();
    let mut rec = larry_discover::model::Record::new("shop.example.org");
    rec.docroot = Some(src.join("httpdocs").display().to_string());
    rec.vhost_root = Some(src.display().to_string());
    rec.exclude_paths = vec![src.join("httpdocs/blog").display().to_string()];
    rec.php_mode = "fpm".into();
    larry_discover::write_inventory(&d.join("inventory.jsonl"), &[rec]).unwrap();
    std::fs::write(
        d.join("sites.toml"),
        format!("[[site]]\ndomain = \"shop.example.org\"\ndocroot = \"public\"\nrewrite_paths = true\n[site.fpm]\nuser = \"{me}\"\ngroup = \"{my_group}\"\n"),
    )
    .unwrap();

    // preflight hands the facts over; the target side reads them and reports
    let (_, out) = larry(&d, &["preflight"]);
    assert!(out.contains("ok    facts for web1"), "{out}");
    let t = Command::new(env!("CARGO_BIN_EXE_larry"))
        .args(["target", "preflight", "--vhost-base"])
        .arg(d.join("vhosts"))
        .arg("--incoming")
        .arg(d.join("incoming"))
        .output()
        .unwrap();
    let t = String::from_utf8_lossy(&t.stdout).to_string();
    assert!(t.contains("site shop.example.org") && !t.contains("FAIL  site"), "{t}");
    assert!(!t.contains("no preflight.json"), "{t}");

    // dry run changes nothing on the target
    let (code, out) = larry(&d, &["sync", "--dry-run"]);
    assert_eq!(code, 0, "{out}");
    assert!(std::fs::read_dir(d.join("incoming")).unwrap().all(|e| e.unwrap().file_name() == "preflight.json"), "dry run pushed something: {out}");

    // first sync
    let (code, out) = larry(&d, &["sync"]);
    assert_eq!(code, 0, "{out}");
    let pkg = d.join("incoming/shop.example.org");
    assert!(pkg.join("manifest.json").is_file() && pkg.join("docroot/index.php").is_file() && pkg.join("extra/logs/access.log").is_file(), "{out}");
    assert!(!pkg.join("docroot/blog").exists() && !pkg.join("extra/httpdocs").exists(), "nested tree and docroot stay out of the other trees");

    // apply: dry run first, then for real
    let (code, out) = apply(&d, &["--web-group", &my_group, "--dry-run"]);
    assert_eq!(code, 0, "{out}");
    assert!(out.contains("would rewrite") && out.contains("would copy docroot") && !d.join("vhosts/shop.example.org/public/index.php").exists(), "{out}");
    let (code, out) = apply(&d, &["--web-group", &my_group]);
    assert!(code == 0 || code == 2, "apply failed: {out}");
    assert!(!out.contains("FAILED"), "{out}");
    let doc = d.join("vhosts/shop.example.org/public");
    let new_root = doc.display().to_string();
    let index = std::fs::read_to_string(doc.join("index.php")).unwrap();
    assert!(index.contains(&format!("'{new_root}'")) && !index.contains(&old), "PHP paths rewritten: {index}");
    assert_eq!(std::fs::read_to_string(doc.join("page.html")).unwrap(), format!("see {old}"), "only PHP files are rewritten");
    assert!(d.join("vhosts/shop.example.org/logs/access.log").is_file());
    let mode = |p: &Path| std::os::unix::fs::PermissionsExt::mode(&std::fs::metadata(p).unwrap().permissions()) & 0o777;
    assert_eq!((mode(&doc), mode(&doc.join("index.php"))), (0o750, 0o640));
    assert!(
        std::fs::read_dir(d.join("bak")).unwrap().all(|e| !e.unwrap().file_name().to_string_lossy().ends_with(".files.tar.gz")),
        "nothing to snapshot the first time"
    );

    // second round: a changed file and a removed one; with --mirror the removed file moves aside
    std::fs::write(src.join("httpdocs/page.html"), "changed").unwrap();
    std::fs::write(doc.join("only-on-target.txt"), "x").unwrap();
    let (code, out) = larry(&d, &["sync", "--files", "--mirror"]);
    assert_eq!(code, 0, "{out}");
    let (code, out) = apply(&d, &["--web-group", &my_group, "--mirror"]);
    assert!(code == 0 || code == 2, "{out}");
    assert_eq!(std::fs::read_to_string(doc.join("page.html")).unwrap(), "changed");
    assert!(!doc.join("only-on-target.txt").exists(), "mirror removed it");
    let moved: Vec<_> = walk(&d.join("bak")).into_iter().filter(|p| p.ends_with("only-on-target.txt")).collect();
    assert_eq!(moved.len(), 1, "the removed file is in the backup, not gone");
    assert!(
        std::fs::read_dir(d.join("bak")).unwrap().any(|e| e.unwrap().file_name().to_string_lossy().ends_with(".files.tar.gz")),
        "second run snapshots first"
    );
}

fn walk(p: &Path) -> Vec<PathBuf> {
    let mut v = vec![];
    if let Ok(rd) = std::fs::read_dir(p) {
        for e in rd.flatten() {
            let q = e.path();
            if q.is_dir() {
                v.extend(walk(&q));
            } else {
                v.push(q);
            }
        }
    }
    v
}
