//! Command builders for `ssh` and `rsync`, and the external-tool check used by `preflight`.
//! Every call is an argument list; the generated ssh config does the host-key pinning.

use crate::{ssh, Cmd};
use std::path::Path;

fn no_space(what: &str, p: &str) -> Result<(), String> {
    // rsync -e splits its command on spaces, so a path with one would be mis-parsed.
    if p.is_empty() || p.chars().any(|c| c.is_whitespace() || c == '"' || c == '\'') {
        return Err(format!("{what} '{p}' must not contain whitespace or quotes (rsync -e cannot carry it)"));
    }
    Ok(())
}

/// `ssh -F <config> larry-<target> <remote command...>`; stdin is /dev/null.
pub fn ssh_cmd(ssh_config: &str, target: &str, remote: &[&str]) -> Result<Cmd, String> {
    no_space("ssh config path", ssh_config)?;
    Ok(Cmd::new("ssh").args(["-F", ssh_config]).arg(ssh::alias(target)).args(remote))
}

/// Push files into the target's drop directory. With the forced `rrsync` of the key login the
/// destination is relative to the drop directory (`./`); with password login pass its absolute path.
pub fn rsync_push(ssh_config: &str, target: &str, sources: &[&Path], dest: &str) -> Result<Cmd, String> {
    no_space("ssh config path", ssh_config)?;
    no_space("destination", dest)?;
    if sources.is_empty() {
        return Err("nothing to send".into());
    }
    let mut c = Cmd::new("rsync").args(["-a", "--partial", "--mkpath", "-e"]).arg(format!("ssh -F {ssh_config}"));
    for s in sources {
        let s = s.to_string_lossy();
        no_space("file", &s)?;
        c = c.arg(s.as_ref());
    }
    Ok(c.arg(format!("{}:{dest}", ssh::alias(target))))
}

/// Options for [`rsync_tree`].
#[derive(Debug, Default, Clone)]
pub struct TreeOpts<'a> {
    /// Patterns anchored at the transfer root, e.g. `/blog`.
    pub excludes: &'a [String],
    /// Remove files on the receiving side that are gone here (drop directory only; the real
    /// sites change only through `target apply --mirror`).
    pub delete: bool,
    pub dry_run: bool,
}

/// Push a directory tree: `rsync -a src/ target:dest/`, creating missing parent directories.
/// Owner and group are not sent (the receiving account is not root), devices and specials are skipped.
pub fn rsync_tree(ssh_config: &str, target: &str, src: &Path, dest: &str, o: &TreeOpts) -> Result<Cmd, String> {
    no_space("ssh config path", ssh_config)?;
    no_space("destination", dest)?;
    let s = src.to_string_lossy();
    no_space("source directory", &s)?;
    let mut c = Cmd::new("rsync")
        .args(["-a", "--partial", "--mkpath", "--no-owner", "--no-group", "--no-devices", "--no-specials", "-e"])
        .arg(format!("ssh -F {ssh_config}"));
    if o.delete {
        c = c.arg("--delete");
    }
    if o.dry_run {
        c = c.arg("--dry-run");
    }
    for e in o.excludes {
        c = c.arg(format!("--exclude={e}"));
    }
    Ok(c.arg(format!("{}/", s.trim_end_matches('/'))).arg(format!("{}:{}/", ssh::alias(target), dest.trim_end_matches('/'))))
}

/// Reachability probe: a dry-run rsync of an empty directory into the drop directory. It works through
/// the forced `rrsync` (a plain `ssh host true` would be refused) and changes nothing on the target.
pub fn rsync_probe(ssh_config: &str, target: &str, empty_dir: &Path, dest: &str) -> Result<Cmd, String> {
    no_space("ssh config path", ssh_config)?;
    no_space("destination", dest)?;
    let dir = empty_dir.to_string_lossy();
    no_space("probe directory", &dir)?;
    Ok(Cmd::new("rsync")
        .args(["-a", "--dry-run", "-e"])
        .arg(format!("ssh -F {ssh_config} -o BatchMode=yes -o ConnectTimeout=10"))
        .arg(format!("{}/", dir.trim_end_matches('/')))
        .arg(format!("{}:{dest}", ssh::alias(target))))
}

pub struct ToolSpec {
    pub label: &'static str,
    /// Any one of these satisfies the requirement (e.g. `mysqldump` or `mariadb-dump`).
    pub any_of: &'static [&'static str],
    pub version_args: &'static [&'static str],
}

#[derive(Debug)]
pub struct ToolStatus {
    pub label: &'static str,
    pub found: Option<String>,
    pub version: Option<String>,
}

/// Needed on the source (the machine that pushes).
pub const SOURCE_TOOLS: &[ToolSpec] = &[
    ToolSpec { label: "ssh", any_of: &["ssh"], version_args: &["-V"] },
    ToolSpec { label: "ssh-keygen", any_of: &["ssh-keygen"], version_args: &[] },
    ToolSpec { label: "rsync", any_of: &["rsync"], version_args: &["--version"] },
    ToolSpec { label: "mysqldump", any_of: &["mysqldump", "mariadb-dump"], version_args: &["--version"] },
    ToolSpec { label: "mysql", any_of: &["mysql", "mariadb"], version_args: &["--version"] },
    ToolSpec { label: "apache2ctl", any_of: &["apache2ctl"], version_args: &["-v"] },
];

/// Needed on a target (run as root by `larry target ...`). `php-fpm<ver>` is checked per site.
pub const TARGET_TOOLS: &[ToolSpec] = &[
    ToolSpec { label: "rsync", any_of: &["rsync"], version_args: &["--version"] },
    ToolSpec { label: "mysqldump", any_of: &["mysqldump", "mariadb-dump"], version_args: &["--version"] },
    ToolSpec { label: "mysql", any_of: &["mysql", "mariadb"], version_args: &["--version"] },
    ToolSpec { label: "apache2ctl", any_of: &["apache2ctl"], version_args: &["-v"] },
    ToolSpec { label: "setfacl", any_of: &["setfacl"], version_args: &["--version"] },
    ToolSpec { label: "getfacl", any_of: &["getfacl"], version_args: &["--version"] },
    ToolSpec { label: "setpriv", any_of: &["setpriv"], version_args: &["--version"] },
    ToolSpec { label: "sshd", any_of: &["sshd"], version_args: &[] },
    ToolSpec { label: "certbot", any_of: &["certbot"], version_args: &["--version"] },
];

/// First of `names` found in PATH or in an sbin directory (not always in a normal user's PATH).
pub fn locate(names: &[&str]) -> Option<String> {
    crate::find_tool(names).or_else(|| {
        // sbin directories are often not in a normal user's PATH
        names.iter().find(|n| ["/usr/sbin", "/sbin"].iter().any(|d| Path::new(d).join(n).is_file())).map(|n| n.to_string())
    })
}

pub fn check_tools(specs: &[ToolSpec]) -> Vec<ToolStatus> {
    specs
        .iter()
        .map(|s| {
            let found = locate(s.any_of);
            let version = found.as_ref().filter(|_| !s.version_args.is_empty()).and_then(|f| {
                let bin = ["/usr/sbin", "/sbin"].iter().map(|d| Path::new(d).join(f)).find(|p| p.is_file());
                let out = match (crate::find_tool(&[f.as_str()]), bin) {
                    (None, Some(p)) => Cmd::new(p).args(s.version_args).run().ok()?,
                    _ => Cmd::new(f).args(s.version_args).run().ok()?,
                };
                let text = if out.stdout.trim().is_empty() { out.stderr } else { out.stdout };
                text.lines().find(|l| !l.trim().is_empty()).map(|l| l.trim().to_string())
            });
            ToolStatus { label: s.label, found, version }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commands_are_argument_lists_with_the_pinned_config() {
        let c = rsync_push("/root/larry/ssh_config", "web1", &[Path::new("/var/tmp/larry/a.db.sql.gz"), Path::new("/var/tmp/larry/a.db.sql.gz.sha256")], "./")
            .unwrap();
        assert_eq!(
            c.display(),
            "rsync -a --partial --mkpath -e 'ssh -F /root/larry/ssh_config' /var/tmp/larry/a.db.sql.gz /var/tmp/larry/a.db.sql.gz.sha256 larry-web1:./"
        );
        assert_eq!(ssh_cmd("/c", "web1", &["true"]).unwrap().display(), "ssh -F /c larry-web1 true");
        assert!(rsync_push("/root/my config", "web1", &[Path::new("/a")], "./").is_err());
        assert!(rsync_push("/c", "web1", &[Path::new("/a b")], "./").is_err());
        assert!(rsync_push("/c", "web1", &[], "./").is_err());
        assert_eq!(
            rsync_probe("/c", "web1", Path::new("/tmp/empty"), "./").unwrap().display(),
            "rsync -a --dry-run -e 'ssh -F /c -o BatchMode=yes -o ConnectTimeout=10' /tmp/empty/ larry-web1:./"
        );
    }

    #[test]
    fn tool_check_reports_found_and_missing() {
        const SPECS: &[ToolSpec] = &[
            ToolSpec { label: "sh", any_of: &["sh"], version_args: &["-c", "echo v1"] },
            ToolSpec { label: "nothing", any_of: &["no-such-tool-xyz", "also-missing-xyz"], version_args: &["--version"] },
        ];
        let r = check_tools(SPECS);
        assert_eq!((r[0].found.as_deref(), r[0].version.as_deref()), (Some("sh"), Some("v1")));
        assert!(r[1].found.is_none() && r[1].version.is_none());
    }
}
