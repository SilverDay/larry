//! `larry cleanup` on a target, as root: remove the sshd Match block (after a backup), lock and
//! expire the transfer user, archive the drop directory, check that certificates renew here.

use larry_transport::{ssh, Cmd};
use std::path::PathBuf;

pub struct Opts {
    pub target: String,
    pub user: String,
    pub sshd_config: PathBuf,
    pub incoming: PathBuf,
    pub certbot: bool,
    pub dry_run: bool,
}

pub fn run(o: &Opts, stamp: &str) -> Result<u8, String> {
    let mut warned = 0;
    let mut say = |l: String| {
        if l.starts_with("WARN") {
            warned += 1;
        }
        println!("{l}");
    };
    let dry = o.dry_run;
    // 1. sshd
    let sshd = ssh::Sshd::find(&o.sshd_config)?;
    let text = std::fs::read_to_string(&o.sshd_config).map_err(|e| format!("{}: {e}", o.sshd_config.display()))?;
    if ssh::remove_block(&text, &o.target)?.1 {
        if dry {
            say(format!("would remove the larry block '{}' from {} (after a backup)", o.target, o.sshd_config.display()));
        } else {
            let b = ssh::remove_applied(&sshd, &o.target, stamp)?;
            say(format!("sshd_config: block removed and verified (backup: {}). Reload sshd to activate it.", b.map(|p| p.display().to_string()).unwrap_or_default()));
        }
    } else {
        say(format!("sshd_config has no larry block for '{}'", o.target));
    }
    // 2. the transfer user
    let exists = Cmd::new("id").args(["-u", &o.user]).run().map(|r| r.success()).unwrap_or(false);
    if !exists {
        say(format!("user {} does not exist; nothing to lock", o.user));
    } else if dry {
        say(format!("would run: usermod --lock --expiredate 1 {}", o.user));
    } else {
        Cmd::new("usermod").args(["--lock", "--expiredate", "1", &o.user]).run_checked().map_err(|e| e.to_string())?;
        say(format!("user {} locked and expired", o.user));
    }
    // 3. the drop directory is renamed, never deleted
    match std::fs::symlink_metadata(&o.incoming) {
        Ok(m) if m.is_dir() => {
            let mut name = o.incoming.file_name().unwrap().to_os_string();
            name.push(format!(".{stamp}"));
            let to = o.incoming.with_file_name(name);
            if dry {
                say(format!("would rename {} to {}", o.incoming.display(), to.display()));
            } else {
                if to.exists() {
                    return Err(format!("{} already exists", to.display()));
                }
                std::fs::rename(&o.incoming, &to).map_err(|e| format!("{}: {e}", o.incoming.display()))?;
                std::fs::set_permissions(&to, std::os::unix::fs::PermissionsExt::from_mode(0o700)).map_err(|e| format!("{}: {e}", to.display()))?;
                say(format!("drop directory archived as {} (mode 0700)", to.display()));
            }
        }
        _ => say(format!("{} is not a directory; nothing to archive", o.incoming.display())),
    }
    // 4. renewal on this server
    if o.certbot {
        if dry {
            say("would run: certbot renew --dry-run".into());
        } else {
            match Cmd::new("certbot").args(["renew", "--dry-run"]).run() {
                Ok(r) if r.success() => say("certbot renew --dry-run: ok".into()),
                Ok(r) => say(format!("WARN: certbot renew --dry-run failed (DNS must point here first): {}", r.stderr.lines().last().unwrap_or("").trim())),
                Err(e) => say(format!("WARN: {e}")),
            }
        }
    }
    Ok(if warned > 0 { 2 } else { 0 })
}
