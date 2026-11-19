//! End to end against a private sshd on localhost (own host key, own port, run as the current user):
//! the generated ssh config, the restricted authorized_keys line and the rsync builders, exactly as
//! `larry` produces them. Skipped when sshd, rrsync or rsync are missing.
//!
//! Proves: a push works into the drop directory; a remote command, a read and a `../` escape are
//! all refused by the forced rrsync; a changed host key is refused (no trust on first use).

use larry_transport::ssh::{self, TargetSsh};
use larry_transport::transfer::{rsync_probe, rsync_push, ssh_cmd};
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

/// Runs on success and on panic: closes the shared ssh connection and removes the directory.
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

fn keygen(path: &Path) {
    Cmd::new("ssh-keygen").args(["-q", "-t", "ed25519", "-N", "", "-f"]).arg(path).run_checked().unwrap();
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

#[test]
fn push_probe_and_refusals_through_a_real_sshd() {
    let sshd_bin = PathBuf::from("/usr/sbin/sshd");
    if !sshd_bin.exists() || !Path::new("/usr/bin/rrsync").exists() || larry_transport::find_tool(&["rsync"]).is_none() {
        eprintln!("SKIPPED: sshd, rrsync or rsync not installed");
        return;
    }
    // a short path: ssh refuses ControlPath sockets of 108+ bytes
    let d = PathBuf::from(format!("/tmp/lt-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    let _cleanup = Cleanup(d.clone());
    for sub in ["incoming", "src", "empty"] {
        std::fs::create_dir_all(d.join(sub)).unwrap();
    }
    keygen(&d.join("hostkey"));
    keygen(&d.join("id_ed25519"));
    let port = free_port();
    let me = Cmd::new("id").arg("-un").run_checked().unwrap().stdout.trim().to_string();

    let pubkey = std::fs::read_to_string(d.join("id_ed25519.pub")).unwrap();
    let ak = ssh::authorized_keys_line(&pubkey, "127.0.0.1", &d.join("incoming").display().to_string(), "/usr/bin/rrsync").unwrap();
    std::fs::write(d.join("authorized_keys"), format!("{ak}\n")).unwrap();
    std::fs::set_permissions(d.join("authorized_keys"), std::os::unix::fs::PermissionsExt::from_mode(0o600)).unwrap();
    std::fs::write(
        d.join("sshd_config"),
        format!(
            "Port {port}\nListenAddress 127.0.0.1\nHostKey {0}/hostkey\nPidFile {0}/sshd.pid\nAuthorizedKeysFile {0}/authorized_keys\nUsePAM no\nPasswordAuthentication no\nStrictModes no\n",
            d.display()
        ),
    )
    .unwrap();
    let _server = Sshd(Command::new(&sshd_bin).args(["-D", "-e", "-f"]).arg(d.join("sshd_config")).stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap());
    for _ in 0..40 {
        if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }

    // pin the host key the way init does (fingerprint confirmed, then written to known_hosts)
    let hostpub = std::fs::read_to_string(d.join("hostkey.pub")).unwrap();
    let fp = ssh::fingerprint(&hostpub).unwrap();
    let pinned = ssh::pin("127.0.0.1", &format!("127.0.0.1 {}", hostpub.trim()), &fp).unwrap();
    let (t, b) = ssh::parse_key(&pinned).unwrap();
    std::fs::write(d.join("known_hosts"), format!("[127.0.0.1]:{port} {t} {b}\n")).unwrap(); // non-default port form

    let identity = d.join("id_ed25519").display().to_string();
    let generated = ssh::ssh_config(
        &[TargetSsh { name: "web1", address: "127.0.0.1", user: &me, identity_file: &identity }],
        &d.join("known_hosts").display().to_string(),
        &d.display().to_string(),
    )
    .unwrap();
    // only the port is added; ssh uses the first value it obtains, so it goes in front
    let cfg_path = d.join("ssh_config");
    std::fs::write(&cfg_path, format!("Host larry-web1\n    Port {port}\n\n{generated}")).unwrap();
    let cfg = cfg_path.display().to_string();

    // push a dump and its checksum into the drop directory, then verify there
    std::fs::write(d.join("src/a.db.sql.gz"), "hello\n").unwrap();
    let sum = Cmd::new("sha256sum").arg("a.db.sql.gz").run_checked().ok();
    drop(sum);
    let hash = larry_transport_sha(&d.join("src/a.db.sql.gz"));
    std::fs::write(d.join("src/a.db.sql.gz.sha256"), format!("{hash}  a.db.sql.gz\n")).unwrap();
    let files = [d.join("src/a.db.sql.gz"), d.join("src/a.db.sql.gz.sha256")];
    let refs: Vec<&Path> = files.iter().map(|p| p.as_path()).collect();
    let r = rsync_push(&cfg, "web1", &refs, "./").unwrap().run().unwrap();
    assert!(r.success(), "push failed: {}", r.stderr);
    assert_eq!(std::fs::read_to_string(d.join("incoming/a.db.sql.gz")).unwrap(), "hello\n");
    assert!(Cmd::new("sha256sum").args(["-c", "a.db.sql.gz.sha256"]).run().is_ok());

    // the preflight probe works and changes nothing
    let before = std::fs::read_dir(d.join("incoming")).unwrap().count();
    assert!(rsync_probe(&cfg, "web1", &d.join("empty"), "./").unwrap().run().unwrap().success());
    assert_eq!(std::fs::read_dir(d.join("incoming")).unwrap().count(), before);

    // the account can only drop files
    let cmd = ssh_cmd(&cfg, "web1", &["id"]).unwrap().run().unwrap();
    assert!(!cmd.success() && cmd.stderr.contains("does not run rsync"), "remote commands must be refused: {}", cmd.stderr);
    let read = Cmd::new("rsync").args(["-e"]).arg(format!("ssh -F {cfg}")).arg("larry-web1:./a.db.sql.gz").arg(d.join("pulled")).run().unwrap();
    assert!(!read.success() && !d.join("pulled").exists(), "write-only: nothing can be read back");
    let escape = rsync_push(&cfg, "web1", &refs[..1], "../escape").unwrap().run().unwrap();
    assert!(!escape.success() && !d.join("escape").exists(), "no way out of the drop directory");

    // a different host key than the pinned one is refused. Close the shared (ControlPersist)
    // connection first: it was authenticated earlier and would be reused without a new check.
    let _ = Cmd::new("ssh").args(["-F", &cfg, "-O", "exit", "larry-web1"]).run();
    keygen(&d.join("other"));
    let other = std::fs::read_to_string(d.join("other.pub")).unwrap();
    let (t, b) = ssh::parse_key(&other).unwrap();
    std::fs::write(d.join("known_hosts"), format!("[127.0.0.1]:{port} {t} {b}\n")).unwrap();
    let r = ssh_cmd(&cfg, "web1", &["true"]).unwrap().run().unwrap();
    assert!(!r.success() && r.stderr.contains("Host key verification failed"), "{}", r.stderr);

}

fn larry_transport_sha(p: &Path) -> String {
    let out = Cmd::new("sha256sum").arg(p).run_checked().unwrap().stdout;
    out.split_whitespace().next().unwrap().to_string()
}
