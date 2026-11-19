//! `larry provision` on a target: pool user, pool file, Apache vhost, directories, certificates;
//! or adoption of a vhost that already exists.

use crate::manifest::Manifest;
use crate::perms::{ownership_steps, Ownership};
use crate::steps::Step;
use crate::{pool, vhost};
use larry_transport::Cmd;
use std::path::{Path, PathBuf};

/// Where things live on the target. Defaults are Debian's; tests point them at a temp tree.
#[derive(Debug, Clone)]
pub struct Env {
    pub vhost_base: PathBuf,
    pub apache_sites: PathBuf,
    pub php_etc: PathBuf,
    pub letsencrypt: PathBuf,
    pub incoming: PathBuf,
    pub backup_dir: PathBuf,
    pub web_group: String,
    pub deploy_user: Option<String>,
}

impl Env {
    pub fn debian(cfg: &larry_config::Layout, incoming: &Path) -> Env {
        Env {
            vhost_base: cfg.vhost_base.clone().into(),
            apache_sites: "/etc/apache2/sites-available".into(),
            php_etc: "/etc/php".into(),
            letsencrypt: "/etc/letsencrypt".into(),
            incoming: incoming.into(),
            backup_dir: "/var/backups/larry".into(),
            web_group: cfg.web_group.clone(),
            deploy_user: cfg.deploy_acl_user.clone(),
        }
    }
    pub fn package_dir(&self, domain: &str) -> PathBuf {
        self.incoming.join(domain)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Adopted {
    pub conf: PathBuf,
    /// The pool found through the vhost's `proxy:unix:` socket.
    pub pool_file: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Resolved {
    pub vhost_root: PathBuf,
    pub docroot: PathBuf,
    pub pool_user: String,
    pub pool_group: String,
    pub php_version: String,
    pub adopted: Option<Adopted>,
}

fn under(p: &Path, base: &Path) -> bool {
    p.starts_with(base) && p != base
}

/// Work out where the site lives and who owns it: from an existing vhost if there is one,
/// from the manifest otherwise.
pub fn resolve(m: &Manifest, env: &Env, default_php: &str) -> Result<Resolved, String> {
    let php_version = m.fpm.php_version.clone().unwrap_or_else(|| default_php.to_string());
    let base = std::fs::canonicalize(&env.vhost_base).map_err(|e| format!("{}: {e}", env.vhost_base.display()))?;
    let conf = env.apache_sites.join(vhost::conf_name(&m.domain));
    if !conf.is_file() {
        let vroot = base.join(&m.domain);
        return Ok(Resolved {
            docroot: vroot.join(&m.docroot),
            vhost_root: vroot,
            pool_user: m.fpm.user.clone(),
            pool_group: m.fpm.group.clone(),
            php_version,
            adopted: None,
        });
    }
    let mut text = std::fs::read_to_string(&conf).map_err(|e| format!("{}: {e}", conf.display()))?;
    let ssl = env.apache_sites.join(format!("{}-le-ssl.conf", m.domain));
    if let Ok(t) = std::fs::read_to_string(&ssl) {
        text.push('\n');
        text.push_str(&t);
    }
    let roots = vhost::docroots_of(&text);
    if roots.len() != 1 {
        return Err(format!("{}: expected one DocumentRoot, found {}: {}", m.domain, roots.len(), roots.join(", ")));
    }
    let docroot = std::fs::canonicalize(&roots[0]).map_err(|_| format!("{}: DocumentRoot {} does not exist", m.domain, roots[0]))?;
    let vroot = docroot.parent().ok_or("DocumentRoot has no parent")?.to_path_buf();
    if !under(&docroot, &base) || !under(&vroot, &base) {
        return Err(format!("{}: docroot {} is not inside a vhost directory under {}; refusing", m.domain, docroot.display(), base.display()));
    }
    let (mut user, mut group, mut pool_file) = (m.fpm.user.clone(), m.fpm.group.clone(), None);
    if m.php {
        let socks = vhost::proxy_sockets(&text);
        if socks.len() != 1 {
            return Err(format!("{}: expected one proxy:unix: PHP-FPM handler, found {}: {}", m.domain, socks.len(), socks.join(", ")));
        }
        let dirs: Vec<PathBuf> = std::fs::read_dir(&env.php_etc).map(|rd| rd.flatten().map(|e| e.path().join("fpm/pool.d")).collect()).unwrap_or_default();
        let refs: Vec<&Path> = dirs.iter().map(|p| p.as_path()).collect();
        let (file, u, g) = pool::find_pool_by_socket(&refs, &socks[0]).ok_or_else(|| format!("{}: no PHP-FPM pool listens on {}", m.domain, socks[0]))?;
        user = u;
        group = g.unwrap_or_else(|| user.clone());
        pool_file = Some(file);
    }
    Ok(Resolved { vhost_root: vroot, docroot, pool_user: user, pool_group: group, php_version, adopted: Some(Adopted { conf, pool_file }) })
}

fn exists(cmd: Cmd) -> bool {
    cmd.run().map(|o| o.success()).unwrap_or(false)
}

/// Steps for one site. Read-only probes (does the user exist?) happen here, the changes in the steps.
pub fn plan_provision(m: &Manifest, env: &Env, r: &Resolved) -> Result<Vec<Step>, String> {
    let mut v = vec![];
    let ver = &r.php_version;
    // user and group
    if !exists(Cmd::new("getent").args(["group", &r.pool_group])) {
        v.push(Step::Run { desc: format!("create group {}", r.pool_group), cmd: Cmd::new("groupadd").args(["--system", &r.pool_group]) });
    }
    if !exists(Cmd::new("id").args(["-u", &r.pool_user])) {
        v.push(Step::Run {
            desc: format!("create user {}", r.pool_user),
            cmd: Cmd::new("useradd").args(["--system", "--no-create-home", "--shell", "/usr/sbin/nologin", "-g", &r.pool_group, &r.pool_user]),
        });
    } else {
        v.push(Step::Note(format!("user {} already exists; reused", r.pool_user)));
    }
    // directories
    for d in [r.vhost_root.clone(), r.docroot.clone(), r.vhost_root.join("logs"), r.vhost_root.join("tmp")] {
        v.push(Step::Mkdir { path: d, mode: 0o750 });
    }
    let o = Ownership { vhost_root: &r.vhost_root, docroot: &r.docroot, pool_user: &r.pool_user, web_group: &env.web_group, deploy_user: None, prune: &[] };
    // a fresh vhost tree is small; an adopted one is left to `target apply`
    if r.adopted.is_none() {
        v.extend(ownership_steps(&o));
    }
    if let Some(u) = &env.deploy_user {
        let acl = format!("u:{u}:--x");
        v.push(Step::Run {
            desc: format!("let {u} traverse the vhost directories"),
            cmd: Cmd::new("setfacl").args(["-m", &acl]).arg(&env.vhost_base).arg(&r.vhost_root),
        });
    }
    // certificates
    for name in &m.tls {
        v.push(Step::Tls { name: name.clone(), from: env.package_dir(&m.domain).join("tls"), letsencrypt: env.letsencrypt.clone() });
    }
    // PHP-FPM pool
    let write_pool = match &r.adopted {
        None => Some(pool::pool_file(&env.php_etc, ver, &pool::pool_name(m))),
        Some(a) if m.manage_pool => a.pool_file.clone(),
        Some(a) => {
            v.push(Step::Note(match &a.pool_file {
                Some(f) => format!("existing pool {} left alone (manage_pool is off)", f.display()),
                None => "existing vhost has no PHP-FPM pool; nothing to manage".into(),
            }));
            None
        }
    };
    if m.php {
        if let Some(path) = write_pool {
            let svc = format!("php{ver}-fpm");
            v.push(Step::Write {
                path,
                content: pool::render(m, ver, &env.vhost_base.to_string_lossy()),
                mode: 0o644,
                test: Some(Cmd::new(format!("php-fpm{ver}")).arg("-t")),
            });
            v.push(Step::Run { desc: format!("start {svc}"), cmd: Cmd::new("systemctl").args(["enable", "--now", &svc]) });
            v.push(Step::Run { desc: format!("reload {svc}"), cmd: Cmd::new("systemctl").args(["reload", &svc]) });
        }
    }
    // Apache vhost
    if r.adopted.is_some() {
        v.push(Step::Note(format!("existing vhost {} adopted; not rewritten", env.apache_sites.join(vhost::conf_name(&m.domain)).display())));
    } else {
        let mods = ["rewrite", "ssl", "headers", "proxy_fcgi", "setenvif"];
        v.push(Step::Run { desc: "enable Apache modules".into(), cmd: Cmd::new("a2enmod").args(mods) });
        v.push(Step::Write {
            path: env.apache_sites.join(vhost::conf_name(&m.domain)),
            content: vhost::render(m, ver, &env.vhost_base.to_string_lossy()),
            mode: 0o644,
            test: Some(Cmd::new("apache2ctl").arg("configtest")),
        });
        v.push(Step::Run { desc: "enable the site".into(), cmd: Cmd::new("a2ensite").arg(vhost::conf_name(&m.domain)) });
        v.push(Step::Run { desc: "reload apache2".into(), cmd: Cmd::new("systemctl").args(["reload", "apache2"]) });
    }
    Ok(v)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::sample;

    fn env(tag: &str) -> (Env, PathBuf) {
        let d = std::env::temp_dir().join(format!("larry-prov-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        for s in ["vhosts", "sites", "php/8.3/fpm/pool.d", "le", "incoming"] {
            std::fs::create_dir_all(d.join(s)).unwrap();
        }
        let e = Env {
            vhost_base: d.join("vhosts"),
            apache_sites: d.join("sites"),
            php_etc: d.join("php"),
            letsencrypt: d.join("le"),
            incoming: d.join("incoming"),
            backup_dir: d.join("bak"),
            web_group: "www-data".into(),
            deploy_user: None,
        };
        (e, d)
    }

    fn text(steps: &[Step]) -> String {
        steps.iter().map(|s| s.describe()).collect::<Vec<_>>().join("\n")
    }

    #[test]
    fn fresh_site_gets_user_dirs_pool_vhost_and_certificate() {
        let (e, d) = env("fresh");
        let m = sample();
        let r = resolve(&m, &e, "8.3").unwrap();
        assert!(r.adopted.is_none() && r.docroot.ends_with("shop.example.org/public"));
        let t = text(&plan_provision(&m, &e, &r).unwrap());
        assert!(t.contains("useradd --system --no-create-home --shell /usr/sbin/nologin -g php-shop-example-org php-shop-example-org"));
        assert!(t.contains("/logs (mode 0750)") && t.contains("/tmp (mode 0750)"));
        assert!(t.contains("install certificate 'shop.example.org'"));
        let (pool_i, vh_i) = (t.find("shop-example-org.conf").unwrap(), t.find("shop.example.org.conf").unwrap());
        assert!(pool_i < vh_i, "the pool exists before the vhost points at its socket");
        assert!(t.contains("php-fpm8.3 -t") && t.contains("apache2ctl configtest") && t.contains("systemctl reload php8.3-fpm"));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn existing_vhost_is_adopted_and_its_pool_found_by_socket() {
        let (e, d) = env("adopt");
        let m = sample();
        let doc = e.vhost_base.join("shop.example.org/public");
        std::fs::create_dir_all(&doc).unwrap();
        std::fs::write(
            e.apache_sites.join("shop.example.org.conf"),
            format!("<VirtualHost *:80>\nDocumentRoot {}\nSetHandler \"proxy:unix:/run/php/legacy.sock|fcgi://localhost/\"\n</VirtualHost>", doc.display()),
        )
        .unwrap();
        std::fs::write(e.php_etc.join("8.3/fpm/pool.d/legacy.conf"), "[legacy]\nuser = php-legacy\ngroup = php-legacy\nlisten = /run/php/legacy.sock\n")
            .unwrap();
        let r = resolve(&m, &e, "8.3").unwrap();
        assert_eq!(r.pool_user, "php-legacy");
        assert!(r.adopted.as_ref().unwrap().pool_file.as_ref().unwrap().ends_with("legacy.conf"));
        let t = text(&plan_provision(&m, &e, &r).unwrap());
        assert!(t.contains("left alone (manage_pool is off)") && t.contains("adopted; not rewritten"));
        assert!(!t.contains("write "), "nothing is rewritten");
        let mut managed = m.clone();
        managed.manage_pool = true;
        assert!(text(&plan_provision(&managed, &e, &r).unwrap()).contains("legacy.conf"));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn docroot_outside_the_vhost_base_is_refused() {
        let (e, d) = env("outside");
        let m = sample();
        std::fs::create_dir_all(d.join("elsewhere/public")).unwrap();
        std::fs::write(e.apache_sites.join("shop.example.org.conf"), format!("DocumentRoot {}/elsewhere/public\n", d.display())).unwrap();
        assert!(resolve(&m, &e, "8.3").unwrap_err().contains("not inside a vhost directory"));
        let _ = std::fs::remove_dir_all(&d);
    }
}
