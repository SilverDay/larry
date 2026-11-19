//! `larry cutover` on the source. Opt-in write freeze (a 503 maintenance page for the moved sites
//! only), the final sync, and a check of each site on the target with `curl --resolve`.
//! Changing DNS stays the admin's step.

use larry_config::MigrationConfig;
use larry_discover::model::Record;
use larry_transport::Cmd;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

pub const CONF_NAME: &str = "larry-maintenance";

fn re_escape(host: &str) -> String {
    host.replace('.', "\\.")
}

/// An Apache snippet answering 503 for these host names only. `Redirect 503 /` inside `<If>` works
/// without editing any vhost; the port is allowed in the host header.
pub fn maintenance_conf(hosts: &[String]) -> String {
    let alt = hosts.iter().map(|h| re_escape(h)).collect::<Vec<_>>().join("|");
    format!(
        "# written by larry cutover; remove with `larry cutover --unfreeze`\n<If \"%{{HTTP_HOST}} =~ /^({alt})(:[0-9]+)?$/i\">\n    Redirect 503 /\n    ErrorDocument 503 \"<html><body><h1>Down for maintenance</h1><p>This site is moving to a new server and will be back shortly.</p></body></html>\"\n</If>\n"
    )
}

pub fn hosts_of(recs: &[&Record]) -> Vec<String> {
    let mut v: Vec<String> = recs.iter().flat_map(|r| std::iter::once(r.domain.clone()).chain(r.aliases.iter().cloned())).collect();
    v.sort();
    v.dedup();
    v
}

pub struct Apache {
    pub conf_available: PathBuf,
}

impl Apache {
    pub fn debian() -> Apache {
        Apache { conf_available: "/etc/apache2/conf-available".into() }
    }

    fn path(&self) -> PathBuf {
        self.conf_available.join(format!("{CONF_NAME}.conf"))
    }

    /// Write the snippet, enable it, test the whole config and reload; any failure undoes it.
    pub fn freeze(&self, hosts: &[String]) -> Result<(), String> {
        let p = self.path();
        std::fs::write(&p, maintenance_conf(hosts)).map_err(|e| format!("{}: {e}", p.display()))?;
        let undo = |why: String| -> String {
            let _ = Cmd::new("a2disconf").arg(CONF_NAME).run();
            let _ = std::fs::remove_file(&p);
            format!("{why}; maintenance page removed again")
        };
        Cmd::new("a2enconf").arg(CONF_NAME).run_checked().map_err(|e| undo(e.to_string()))?;
        Cmd::new("apache2ctl").arg("configtest").run_checked().map_err(|e| undo(e.to_string()))?;
        Cmd::new("systemctl").args(["reload", "apache2"]).run_checked().map_err(|e| undo(e.to_string()))?;
        Ok(())
    }

    pub fn unfreeze(&self) -> Result<bool, String> {
        let p = self.path();
        if !p.exists() {
            return Ok(false);
        }
        Cmd::new("a2disconf").arg(CONF_NAME).run_checked().map_err(|e| e.to_string())?;
        Cmd::new("apache2ctl").arg("configtest").run_checked().map_err(|e| e.to_string())?;
        Cmd::new("systemctl").args(["reload", "apache2"]).run_checked().map_err(|e| e.to_string())?;
        std::fs::remove_file(&p).map_err(|e| format!("{}: {e}", p.display()))?;
        Ok(true)
    }
}

#[derive(Debug, PartialEq)]
pub enum Verdict {
    Ok(u16),
    Review(u16),
    Fail(String),
}

pub fn classify(code: u16) -> Verdict {
    match code {
        200..=399 => Verdict::Ok(code),
        401 | 403 => Verdict::Review(code),
        c => Verdict::Fail(format!("HTTP {c}")),
    }
}

/// The command that asks the target for the site, bypassing DNS.
pub fn check_cmd(ip: &IpAddr, host: &str, https: bool) -> Cmd {
    let (scheme, port) = if https { ("https", 443) } else { ("http", 80) };
    Cmd::new("curl").args(["-sS", "-o", "/dev/null", "-m", "20", "-w", "%{http_code}", "--resolve"]).arg(format!("{host}:{port}:{ip}")).arg(format!("{scheme}://{host}/"))
}

pub fn check(ip: &IpAddr, host: &str, https: bool) -> Verdict {
    match check_cmd(ip, host, https).run() {
        Ok(o) if o.success() => o.stdout.trim().parse::<u16>().map(classify).unwrap_or_else(|_| Verdict::Fail(format!("unexpected output '{}'", o.stdout.trim()))),
        Ok(o) => Verdict::Fail(o.stderr.trim().to_string()),
        Err(e) => Verdict::Fail(e.to_string()),
    }
}

pub fn target_ip(cfg: &MigrationConfig, name: &str) -> Result<IpAddr, String> {
    let t = cfg.targets.get(name).ok_or_else(|| format!("unknown target '{name}'"))?;
    let h = t.address.as_deref().unwrap_or(&t.host);
    if let Ok(ip) = h.parse() {
        return Ok(ip);
    }
    let out = Cmd::new("getent").args(["ahostsv4", h]).run_checked().map_err(|e| format!("cannot resolve {h}: {e}"))?;
    out.stdout.split_whitespace().next().and_then(|s| s.parse().ok()).ok_or_else(|| format!("cannot resolve {h}"))
}

pub struct Opts {
    pub freeze_source: bool,
    pub unfreeze: bool,
    pub check_only: bool,
    pub mirror: bool,
    pub dry_run: bool,
    pub only: Vec<String>,
}

pub fn run(cfg: &MigrationConfig, dir: &Path, o: &Opts, apache: &Apache) -> Result<u8, String> {
    if o.unfreeze {
        if o.dry_run {
            println!("would remove the maintenance page ({})", apache.path().display());
        } else {
            println!("{}", if apache.unfreeze()? { "maintenance page removed" } else { "no maintenance page was installed" });
        }
        return Ok(0);
    }
    let sites = larry_config::SitesFile::load(&dir.join("sites.toml"), cfg).map_err(|e| e.to_string())?;
    let records = larry_discover::read_inventory(&dir.join("inventory.jsonl"))?;
    let chosen: Vec<&larry_config::Site> = sites.site.iter().filter(|s| o.only.is_empty() || o.only.contains(&s.domain)).collect();
    let recs: Vec<&Record> = chosen.iter().filter_map(|s| records.iter().find(|r| r.domain == s.domain && r.skip.is_none())).collect();

    if !o.check_only {
        if o.freeze_source {
            let hosts = hosts_of(&recs);
            if o.dry_run {
                println!("would answer 503 on the source for: {}", hosts.join(", "));
            } else {
                apache.freeze(&hosts)?;
                println!("source: 503 maintenance page active for {} host name(s). Cron jobs and mail still run; stop them yourself if they write.", hosts.len());
            }
        } else {
            println!("note: writes on the source are NOT frozen (use --freeze-source); changes after this sync will be lost");
        }
        let code = crate::sync::run(cfg, dir, &crate::sync::Opts { files: true, db: true, mirror: o.mirror, dry_run: o.dry_run, resume: false, only: o.only.clone() })?;
        if code == 1 {
            return Err("the final sync failed; the sites on the target are NOT current. The maintenance page (if any) stays; `larry cutover --unfreeze` removes it".into());
        }
        println!("\nNext: on each target run `larry target apply` as root, then `larry cutover --check-only` here.");
        return Ok(code);
    }

    let (mut failed, mut review) = (0, 0);
    for s in chosen {
        let Some(r) = records.iter().find(|r| r.domain == s.domain && r.skip.is_none()) else { continue };
        let target = s.target.clone().or_else(|| cfg.default_target().map(String::from)).ok_or("no target")?;
        let ip = target_ip(cfg, &target)?;
        for host in std::iter::once(&r.domain).chain(r.aliases.iter().take(4)) {
            match check(&ip, host, r.ssl) {
                Verdict::Ok(c) => println!("ok      {host} on {target} ({ip}): HTTP {c}"),
                Verdict::Review(c) => {
                    review += 1;
                    println!("REVIEW  {host} on {target} ({ip}): HTTP {c}");
                }
                Verdict::Fail(e) => {
                    failed += 1;
                    println!("FAIL    {host} on {target} ({ip}): {e}");
                }
            }
        }
    }
    println!("\n{failed} failed, {review} to review. Point DNS at the target only when everything is ok.");
    Ok(if failed > 0 { 1 } else if review > 0 { 2 } else { 0 })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maintenance_snippet_names_only_the_moved_hosts() {
        let c = maintenance_conf(&["a.example.org".into(), "www.a.example.org".into()]);
        assert!(c.contains("=~ /^(a\\.example\\.org|www\\.a\\.example\\.org)(:[0-9]+)?$/i"));
        assert!(c.contains("Redirect 503 /") && c.contains("ErrorDocument 503"));
    }

    #[test]
    fn verdicts_and_the_resolve_command() {
        assert_eq!(classify(200), Verdict::Ok(200));
        assert_eq!(classify(301), Verdict::Ok(301));
        assert_eq!(classify(403), Verdict::Review(403));
        assert!(matches!(classify(500), Verdict::Fail(_)));
        let ip: IpAddr = "192.0.2.10".parse().unwrap();
        let c = check_cmd(&ip, "a.example.org", true).display();
        assert!(c.contains("--resolve a.example.org:443:192.0.2.10") && c.ends_with("https://a.example.org/"), "{c}");
    }

    /// The snippet against a real, private Apache: the listed host gets 503, others are untouched,
    /// including a Host header with a port. Skipped without apache2.
    #[test]
    fn maintenance_page_works_in_a_real_apache() {
        let bin = Path::new("/usr/sbin/apache2");
        let mods = Path::new("/usr/lib/apache2/modules");
        if !bin.exists() || !mods.exists() || larry_transport::find_tool(&["curl"]).is_none() {
            eprintln!("SKIPPED: apache2 or curl missing");
            return;
        }
        let d = PathBuf::from(format!("/tmp/lm-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join("docroot")).unwrap();
        std::fs::write(d.join("docroot/index.html"), "hi").unwrap();
        let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        std::fs::write(d.join("maint.conf"), maintenance_conf(&["a.example.org".into()])).unwrap();
        let m = |n: &str| format!("LoadModule {n}_module {}/mod_{n}.so\n", mods.display());
        let conf = format!(
            "ServerRoot {0}\nPidFile {0}/pid\nListen 127.0.0.1:{port}\nErrorLog {0}/error.log\n{1}TypesConfig /etc/mime.types\nDocumentRoot {0}/docroot\n<Directory {0}/docroot>\nRequire all granted\n</Directory>\nInclude {0}/maint.conf\n",
            d.display(),
            ["mpm_prefork", "authz_core", "alias", "dir", "mime"].iter().map(|n| m(n)).collect::<String>()
        );
        std::fs::write(d.join("httpd.conf"), conf).unwrap();
        let start = Cmd::new(bin).args(["-f"]).arg(d.join("httpd.conf")).args(["-k", "start"]).run().unwrap();
        let get = |host: &str| -> String {
            let o = Cmd::new("curl").args(["-s", "-o", "/dev/null", "-w", "%{http_code}", "-H"]).arg(format!("Host: {host}")).arg(format!("http://127.0.0.1:{port}/")).run().unwrap();
            o.stdout
        };
        let result = (get("a.example.org"), get(&format!("a.example.org:{port}")), get("b.example.org"));
        let _ = Cmd::new(bin).args(["-f"]).arg(d.join("httpd.conf")).args(["-k", "stop"]).run();
        std::thread::sleep(std::time::Duration::from_millis(500));
        let _ = std::fs::remove_dir_all(&d);
        assert!(start.success(), "apache did not start: {}", start.stderr);
        assert_eq!(result, ("503".into(), "503".into(), "200".into()));
    }
}
