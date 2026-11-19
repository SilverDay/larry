//! `larry init`: the wizard. It only helps write plain files; nothing it learns lives anywhere else.
//!
//! Host keys are pinned, not trusted on first use: the key is read with ssh-keyscan, its
//! fingerprint is shown, and the admin types the one printed on the target's console.

use larry_transport::ssh;
use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};

/// Read a host's public key at (address, port).
pub type ScanFn<'a> = dyn Fn(&str, Option<u16>) -> Result<String, String> + 'a;

pub struct Deps<'a> {
    /// Read a host's public key (ssh-keyscan in real use).
    pub scan: &'a ScanFn<'a>,
    /// Create an ed25519 key pair at the path; returns the public key line.
    pub gen_key: &'a dyn Fn(&Path) -> Result<String, String>,
}

struct Target {
    name: String,
    host: String,
    address: String,
    port: Option<u16>,
    user: String,
    incoming: String,
    fingerprint: String,
    known_hosts_line: String,
}

fn q(s: &str) -> String {
    format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
}

struct Prompt<'a> {
    input: &'a mut dyn BufRead,
    out: &'a mut dyn Write,
}

impl Prompt<'_> {
    fn ask(&mut self, question: &str, default: Option<&str>) -> Result<String, String> {
        match default {
            Some(d) if !d.is_empty() => write!(self.out, "{question} [{d}]: "),
            _ => write!(self.out, "{question}: "),
        }
        .map_err(|e| e.to_string())?;
        self.out.flush().ok();
        let mut line = String::new();
        if self.input.read_line(&mut line).map_err(|e| e.to_string())? == 0 {
            return Err("input ended before the wizard finished; nothing was written".into());
        }
        let v = line.trim();
        Ok(if v.is_empty() { default.unwrap_or("").to_string() } else { v.to_string() })
    }

    fn say(&mut self, text: &str) {
        let _ = writeln!(self.out, "{text}");
    }
}

/// Run the wizard in `dir` (where migration.toml, ssh_config and known_hosts are written).
/// Nothing is written until every answer, including every host-key confirmation, has been given.
pub fn run(dir: &Path, input: &mut dyn BufRead, out: &mut dyn Write, deps: &Deps) -> Result<(), String> {
    let toml_path = dir.join("migration.toml");
    if toml_path.exists() {
        return Err(format!("{} already exists: edit it by hand, or move it away to run the wizard again", toml_path.display()));
    }
    std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let dir: PathBuf = std::fs::canonicalize(dir).map_err(|e| e.to_string())?;
    let mut p = Prompt { input, out };

    p.say("larry init: source settings");
    let db_defaults = p.ask("MySQL defaults file with the read-only migration account (mode 0600)", Some("/root/migration-db.cnf"))?;
    let staging = p.ask("Staging directory on this server", Some("/var/tmp/larry"))?;
    let source_ip = p.ask("This server's public IP address as the targets will see it", None)?;
    source_ip.parse::<std::net::IpAddr>().map_err(|_| format!("'{source_ip}' is not an IP address"))?;

    let mut targets: Vec<Target> = vec![];
    loop {
        p.say("");
        let name = p.ask(&format!("Target #{} name, e.g. web1 (empty to finish)", targets.len() + 1), None)?;
        if name.is_empty() {
            break;
        }
        if targets.iter().any(|t| t.name == name) {
            return Err(format!("target '{name}' given twice"));
        }
        let host = p.ask("  host name", None)?;
        let address = p.ask("  IP address to connect to", Some(&host))?;
        let port_text = p.ask("  SSH port", Some("22"))?;
        let port: u16 = port_text.parse().ok().filter(|p| *p != 0).ok_or_else(|| format!("'{port_text}' is not a port number"))?;
        let port = (port != 22).then_some(port);
        let user = p.ask("  transfer account on the target", Some("migrate"))?;
        let incoming = p.ask("  drop directory on the target", Some("/srv/migration-incoming"))?;

        let key = (deps.scan)(&address, port).map_err(|e| format!("{address}: {e}"))?;
        let fp = ssh::fingerprint(&key)?;
        p.say(&format!("  The host key offered by {address} has the fingerprint:\n      {fp}"));
        p.say("  Compare it with the one printed on the target's console, not over this connection:");
        p.say("      ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub");
        let typed = p.ask("  type the fingerprint from the console to pin this key", None)?;
        let line = ssh::pin(&address, port, &key, &typed).map_err(|e| format!("target '{name}': {e}"))?;
        targets.push(Target { name, host, address, port, user, incoming, fingerprint: fp, known_hosts_line: line });
    }
    if targets.is_empty() {
        return Err("no targets given; nothing was written".into());
    }

    // --- everything is confirmed: write the files
    let key_path = dir.join("id_ed25519");
    let pubkey = if key_path.exists() {
        std::fs::read_to_string(dir.join("id_ed25519.pub")).map_err(|e| format!("{}/id_ed25519.pub: {e}", dir.display()))?
    } else {
        (deps.gen_key)(&key_path)?
    };
    let d = |f: &str| dir.join(f).display().to_string();

    let identity = key_path.display().to_string();
    let ssh_targets: Vec<ssh::TargetSsh> =
        targets.iter().map(|t| ssh::TargetSsh { name: &t.name, address: &t.address, user: &t.user, identity_file: &identity, port: t.port }).collect();
    // ssh refuses ControlPath sockets of 108+ bytes: keep them next to the config when that is short
    // enough, otherwise in a private directory under /tmp (sockets are ephemeral).
    let control_dir = if dir.display().to_string().len() <= ssh::MAX_CONTROL_DIR {
        dir.display().to_string()
    } else {
        let user = std::env::var("USER").unwrap_or_else(|_| "user".into());
        let fallback = PathBuf::from(format!("/tmp/larry-cm-{user}"));
        larry_transport::ensure_private_dir(&fallback)?;
        fallback.display().to_string()
    };
    let ssh_config = ssh::ssh_config(&ssh_targets, &d("known_hosts"), &control_dir)?;

    let mut toml = String::from("version = 1\n\n[source]\n");
    toml += &format!("db_defaults_file = {}   # mode 0600\nstaging_dir      = {}\n\n", q(&db_defaults), q(&staging));
    toml += &format!("[ssh]\nconfig_file = {}\nknown_hosts = {}\n", q(&d("ssh_config")), q(&d("known_hosts")));
    for (i, t) in targets.iter().enumerate() {
        toml += &format!(
            "\n[targets.{}]\nhost          = {}\naddress       = {}\n{}host_key      = {}   # confirmed against the target's console\ntransfer_user = {}\nincoming_dir  = {}\n",
            t.name, q(&t.host), q(&t.address), t.port.map(|p| format!("port          = {p}\n")).unwrap_or_default(), q(&t.fingerprint), q(&t.user), q(&t.incoming)
        );
        if i == 0 {
            toml += "default       = true\n";
        }
    }
    toml += "\n[layout]\nvhost_base = \"/srv/vhosts\"\nweb_group  = \"www-data\"\n# deploy_acl_user = \"deploy\"\n\n[fpm.defaults]\npm           = \"ondemand\"\nmax_children = 4\n";
    // the file must be valid before it is written
    larry_config::MigrationConfig::parse(&toml).map_err(|e| format!("internal error, generated migration.toml is invalid: {e}"))?;

    let known = targets.iter().map(|t| t.known_hosts_line.clone()).collect::<Vec<_>>().join("\n") + "\n";
    std::fs::write(dir.join("known_hosts"), known).map_err(|e| e.to_string())?;
    std::fs::write(dir.join("ssh_config"), ssh_config).map_err(|e| e.to_string())?;
    std::fs::write(&toml_path, toml).map_err(|e| e.to_string())?;

    // --- what the admin has to do on each target (printed, never applied from here)
    p.say(&format!("\nWrote {}, {} and {}.", toml_path.display(), d("ssh_config"), d("known_hosts")));
    for t in &targets {
        p.say(&format!("\n=== On target '{}' ({}), as root ===", t.name, t.host));
        p.say(&format!("1. Create the account without a shell or sudo rights, and the drop directory:\n   adduser --system --group --shell /usr/sbin/nologin --home {} {}\n   install -d -o {} -m 0700 {}", t.incoming, t.user, t.user, t.incoming));
        let ak = ssh::authorized_keys_line(&pubkey, &source_ip, &t.incoming, "/usr/bin/rrsync")?;
        p.say(&format!("2. Key login (preferred), in ~{}/.ssh/authorized_keys of that account:\n   {ak}", t.user));
        let block = ssh::sshd_block(&t.name, &t.user, &source_ip)?;
        p.say(&format!(
            "3. Only if you use password login as a fallback, add this to sshd_config (or run\n   `larry target sshd --target {} --user {} --source-ip {source_ip} --apply`, which backs it up and checks it):\n{}",
            t.name,
            t.user,
            block.lines().map(|l| format!("   {l}")).collect::<Vec<_>>().join("\n")
        ));
    }
    p.say("\nNext: larry config check && larry preflight && larry discover");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use larry_transport::Cmd;
    use std::io::Cursor;

    fn tmp(n: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("larry-init-{n}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn host_key(dir: &Path) -> String {
        let p = dir.join("hostkey");
        Cmd::new("ssh-keygen").args(["-q", "-t", "ed25519", "-N", "", "-f"]).arg(&p).run_checked().unwrap();
        std::fs::read_to_string(dir.join("hostkey.pub")).unwrap().trim().to_string()
    }

    fn gen(path: &Path) -> Result<String, String> {
        Cmd::new("ssh-keygen").args(["-q", "-t", "ed25519", "-N", "", "-f"]).arg(path).run_checked().map_err(|e| e.to_string())?;
        std::fs::read_to_string(format!("{}.pub", path.display())).map_err(|e| e.to_string())
    }

    #[test]
    fn wizard_pins_keys_and_writes_valid_files() {
        let d = tmp("ok");
        let key = host_key(&d);
        let fp = ssh::fingerprint(&key).unwrap();
        let script = format!("\n\n192.0.2.1\nweb1\nweb1.example.net\n192.0.2.10\n\n\n\n{fp}\n\n");
        let scan = |_: &str, _: Option<u16>| Ok(format!("192.0.2.10 {key}"));
        let mut out = Vec::new();
        run(&d.join("conf"), &mut Cursor::new(script), &mut out, &Deps { scan: &scan, gen_key: &gen }).unwrap();

        let conf = d.join("conf");
        let cfg = larry_config::MigrationConfig::load(&conf.join("migration.toml")).unwrap();
        let t = &cfg.targets["web1"];
        assert_eq!((t.host_key.as_str(), t.transfer_user.as_str(), t.default), (fp.as_str(), "migrate", true));
        assert_eq!(cfg.source.db_defaults_file, "/root/migration-db.cnf");
        let kh = std::fs::read_to_string(conf.join("known_hosts")).unwrap();
        assert!(kh.starts_with("192.0.2.10 ssh-ed25519 "));
        let sc = std::fs::read_to_string(conf.join("ssh_config")).unwrap();
        assert!(
            sc.contains("StrictHostKeyChecking yes")
                && sc.contains(&format!("UserKnownHostsFile {}/known_hosts", std::fs::canonicalize(&conf).unwrap().display()))
        );
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("restrict,from=\"192.0.2.1\",command=\"/usr/bin/rrsync -wo /srv/migration-incoming\""));
        assert!(text.contains("Match User migrate Address *,!192.0.2.1"));
        assert!(!text.contains("PRIVATE KEY"));

        // a second run refuses to overwrite
        assert!(run(&conf, &mut Cursor::new(""), &mut Vec::new(), &Deps { scan: &scan, gen_key: &gen }).unwrap_err().contains("already exists"));
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn a_non_default_port_is_scanned_pinned_and_configured() {
        let d = tmp("port");
        let key = host_key(&d);
        let fp = ssh::fingerprint(&key).unwrap();
        let script = format!("\n\n192.0.2.1\nweb1\nweb1.example.net\n192.0.2.10\n2222\n\n\n{fp}\n\n");
        let seen = std::cell::Cell::new(None);
        let scan = |_: &str, p: Option<u16>| {
            seen.set(p);
            Ok(format!("[192.0.2.10]:2222 {key}"))
        };
        run(&d.join("conf"), &mut Cursor::new(script), &mut Vec::new(), &Deps { scan: &scan, gen_key: &gen }).unwrap();
        assert_eq!(seen.get(), Some(2222));
        let conf = d.join("conf");
        assert_eq!(larry_config::MigrationConfig::load(&conf.join("migration.toml")).unwrap().targets["web1"].port, Some(2222));
        assert!(std::fs::read_to_string(conf.join("known_hosts")).unwrap().starts_with("[192.0.2.10]:2222 ssh-ed25519 "));
        assert!(std::fs::read_to_string(conf.join("ssh_config")).unwrap().contains("    Port 2222\n"));
        let bad = run(&d.join("conf2"), &mut Cursor::new("\n\n192.0.2.1\nweb1\nh\n192.0.2.10\nssh\n"), &mut Vec::new(), &Deps { scan: &scan, gen_key: &gen });
        assert!(bad.unwrap_err().contains("not a port number"));
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn a_wrong_fingerprint_pins_nothing_and_writes_nothing() {
        let d = tmp("bad");
        let key = host_key(&d);
        let script = "\n\n192.0.2.1\nweb1\nweb1.example.net\n192.0.2.10\n\n\n\nSHA256:attackerscontrolledfingerprint\n";
        let scan = |_: &str, _: Option<u16>| Ok(format!("192.0.2.10 {key}"));
        let err = run(&d.join("conf"), &mut Cursor::new(script), &mut Vec::new(), &Deps { scan: &scan, gen_key: &gen }).unwrap_err();
        assert!(err.contains("does not match"), "{err}");
        assert!(!d.join("conf/migration.toml").exists() && !d.join("conf/known_hosts").exists());

        // ending the input early also writes nothing
        let err = run(&d.join("conf2"), &mut Cursor::new("\n\n192.0.2.1\nweb1\n"), &mut Vec::new(), &Deps { scan: &scan, gen_key: &gen }).unwrap_err();
        assert!(err.contains("input ended"));
        assert!(!d.join("conf2/migration.toml").exists());
        std::fs::remove_dir_all(&d).unwrap();
    }
}
