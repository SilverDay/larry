//! The fixed ownership model: `<pool user>:<web group>`, dirs 0750 / files 0640, ACLs per type
//! (setfacl through `find -type`, never following symlinks), optional deploy-user ACL on the docroot.

use crate::steps::Step;
use larry_transport::Cmd;
use std::path::{Path, PathBuf};

/// `find <root> ( -path p1 -o -path p2 ) -prune -o <rest>`: nested vhost trees are left alone.
pub fn find_pruned(root: &Path, prune: &[PathBuf], rest: &[&str]) -> Cmd {
    let mut c = Cmd::new("find").arg(root);
    if !prune.is_empty() {
        c = c.arg("(");
        for (i, p) in prune.iter().enumerate() {
            if i > 0 {
                c = c.arg("-o");
            }
            c = c.arg("-path").arg(p);
        }
        c = c.args([")", "-prune", "-o"]);
    }
    c.args(rest)
}

pub struct Ownership<'a> {
    pub vhost_root: &'a Path,
    pub docroot: &'a Path,
    pub pool_user: &'a str,
    pub web_group: &'a str,
    pub deploy_user: Option<&'a str>,
    pub prune: &'a [PathBuf],
}

pub fn ownership_steps(o: &Ownership) -> Vec<Step> {
    let owner = format!("{}:{}", o.pool_user, o.web_group);
    let run = |desc: &str, cmd: Cmd| Step::Run { desc: desc.into(), cmd };
    let mut v = vec![
        run("set owner", find_pruned(o.vhost_root, o.prune, &["-exec", "chown", "-h", &owner, "{}", "+"])),
        run("set directory mode 0750", find_pruned(o.vhost_root, o.prune, &["-type", "d", "-exec", "chmod", "0750", "{}", "+"])),
        run("set file mode 0640", find_pruned(o.vhost_root, o.prune, &["-type", "f", "-exec", "chmod", "0640", "{}", "+"])),
    ];
    if let Some(u) = o.deploy_user {
        let (rwx, rw) = (format!("u:{u}:rwx"), format!("u:{u}:rw-"));
        v.push(run("deploy user ACL on directories", find_pruned(o.docroot, o.prune, &["-type", "d", "-exec", "setfacl", "-m", &rwx, "{}", "+"])));
        v.push(run("deploy user ACL on files", find_pruned(o.docroot, o.prune, &["-type", "f", "-exec", "setfacl", "-m", &rw, "{}", "+"])));
        v.push(run("deploy user default ACL", find_pruned(o.docroot, o.prune, &["-type", "d", "-exec", "setfacl", "-d", "-m", &rwx, "{}", "+"])));
    }
    // chmod only writes the ACL mask when an ACL exists, so the group entry is set explicitly
    v.push(run("group ACL on directories", find_pruned(o.vhost_root, o.prune, &["-type", "d", "-exec", "setfacl", "-m", "g::r-x", "{}", "+"])));
    v.push(run("group ACL on files", find_pruned(o.vhost_root, o.prune, &["-type", "f", "-exec", "setfacl", "-m", "g::r--", "{}", "+"])));
    v
}

/// `setpriv` access checks, reported as warnings.
pub fn access_checks(o: &Ownership, pool_group: &str, probe: Option<&Path>) -> Vec<Step> {
    let can = |user: &str, group: &str, flag: &str, path: &Path| {
        Cmd::new("setpriv").args([
            format!("--reuid={user}"),
            format!("--regid={group}"),
            "--init-groups".into(),
            "test".into(),
            flag.into(),
            path.display().to_string(),
        ])
    };
    let mut v = vec![Step::Warn { desc: format!("PHP worker {} can traverse the docroot", o.pool_user), cmd: can(o.pool_user, pool_group, "-x", o.docroot) }];
    if let Some(p) = probe {
        v.push(Step::Warn { desc: format!("PHP worker {} can read {}", o.pool_user, p.display()), cmd: can(o.pool_user, pool_group, "-r", p) });
    }
    v.push(Step::Warn { desc: "Apache (www-data) can traverse the docroot".into(), cmd: can("www-data", o.web_group, "-x", o.docroot) });
    if let Some(u) = o.deploy_user {
        v.push(Step::Warn { desc: format!("deploy user {u} can write the docroot"), cmd: can(u, u, "-w", o.docroot) });
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commands_are_argument_lists_with_per_type_acls_and_pruning() {
        let prune = [PathBuf::from("/srv/vhosts/a/sub")];
        let o = Ownership {
            vhost_root: Path::new("/srv/vhosts/a"),
            docroot: Path::new("/srv/vhosts/a/public"),
            pool_user: "php-a",
            web_group: "www-data",
            deploy_user: Some("deploy"),
            prune: &prune,
        };
        let s: Vec<String> = ownership_steps(&o).iter().map(|s| s.describe()).collect();
        assert!(s[0].contains("find /srv/vhosts/a '(' -path /srv/vhosts/a/sub ')' -prune -o -exec chown -h php-a:www-data '{}' +"));
        assert!(s.iter().any(|l| l.contains("-type d -exec chmod 0750")));
        assert!(s.iter().any(|l| l.contains("-type f -exec setfacl -m g::r--")));
        assert!(s.iter().any(|l| l.contains("find /srv/vhosts/a/public") && l.contains("setfacl -d -m u:deploy:rwx")));
        let no_deploy = Ownership { deploy_user: None, ..o };
        assert!(!ownership_steps(&no_deploy).iter().any(|s| s.describe().contains("deploy")));
    }
}
