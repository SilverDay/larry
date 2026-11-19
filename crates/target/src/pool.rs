//! PHP-FPM pool files: render, locate an existing pool by socket.

use crate::manifest::Manifest;
use larry_config::dashed;
use std::path::{Path, PathBuf};

pub fn pool_name(m: &Manifest) -> String {
    dashed(&m.domain)
}

pub fn socket_path(php_version: &str, pool: &str) -> String {
    format!("/run/php/php{php_version}-fpm-{pool}.sock")
}

pub fn pool_file(php_etc: &Path, php_version: &str, pool: &str) -> PathBuf {
    php_etc.join(php_version).join("fpm/pool.d").join(format!("{pool}.conf"))
}

/// The pool file from the spec's table. `php_version` is the resolved one (the target's default
/// when the site sets none).
pub fn render(m: &Manifest, php_version: &str, vhost_base: &str) -> String {
    let pool = pool_name(m);
    let vhost = format!("{}/{}", vhost_base.trim_end_matches('/'), m.domain);
    let tmp = format!("{vhost}/tmp");
    let f = &m.fpm;
    let mut s = String::new();
    s.push_str(&format!("; written by larry for {}\n", m.domain));
    s.push_str(&format!("[{pool}]\nuser = {}\ngroup = {}\n", f.user, f.group));
    s.push_str(&format!("listen = {}\n", socket_path(php_version, &pool)));
    s.push_str("listen.owner = www-data\nlisten.group = www-data\nlisten.mode = 0660\n");
    s.push_str(&format!("pm = {}\npm.max_children = {}\n", f.pm, f.max_children));
    s.push_str(&format!("pm.process_idle_timeout = {}\npm.max_requests = {}\n", f.process_idle_timeout, f.max_requests));
    let admin = [
        ("open_basedir", format!("{vhost}/:{tmp}/")),
        ("upload_tmp_dir", tmp.clone()),
        ("session.save_path", tmp.clone()),
        ("sys_temp_dir", tmp.clone()),
        ("session.gc_probability", "1".into()),
        ("error_log", format!("{vhost}/logs/php-fpm-error.log")),
    ];
    for (k, v) in admin {
        s.push_str(&format!("php_admin_value[{k}] = {v}\n"));
    }
    s.push_str("php_admin_flag[log_errors] = on\n");
    for (k, v) in &f.php_value {
        s.push_str(&format!("php_value[{k}] = {v}\n"));
    }
    for (k, v) in &f.php_flag {
        s.push_str(&format!("php_flag[{k}] = {v}\n"));
    }
    s
}

/// `key = value` from a pool or ini file (first match; values end at whitespace or `;`).
pub fn ini_value(text: &str, key: &str) -> Option<String> {
    for line in text.lines() {
        let l = line.trim();
        if l.starts_with(';') || l.starts_with('#') {
            continue;
        }
        if let Some((k, v)) = l.split_once('=') {
            if k.trim() == key {
                let v = v.trim().split([' ', '\t', ';']).next().unwrap_or("");
                return Some(v.to_string());
            }
        }
    }
    None
}

/// Find the pool whose `listen =` is this socket, the way deploy v2 did. Returns (file, user, group).
pub fn find_pool_by_socket(pool_dirs: &[&Path], socket: &str) -> Option<(PathBuf, String, Option<String>)> {
    let mut files: Vec<PathBuf> = vec![];
    for d in pool_dirs {
        if let Ok(rd) = std::fs::read_dir(d) {
            files.extend(rd.flatten().map(|e| e.path()).filter(|p| p.extension().is_some_and(|x| x == "conf")));
        }
    }
    files.sort();
    for f in files {
        let Ok(text) = std::fs::read_to_string(&f) else { continue };
        if ini_value(&text, "listen").as_deref() == Some(socket) {
            let user = ini_value(&text, "user")?;
            return Some((f, user, ini_value(&text, "group")));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::sample;

    #[test]
    fn renders_the_spec_defaults() {
        let m = sample();
        let t = render(&m, "8.3", "/srv/vhosts");
        assert!(t.contains("[shop-example-org]\nuser = php-shop-example-org\ngroup = php-shop-example-org\n"));
        assert!(t.contains("listen = /run/php/php8.3-fpm-shop-example-org.sock\n"));
        assert!(t.contains("listen.mode = 0660") && t.contains("pm = ondemand") && t.contains("pm.max_children = 4"));
        assert!(t.contains("php_admin_value[open_basedir] = /srv/vhosts/shop.example.org/:/srv/vhosts/shop.example.org/tmp/"));
        assert!(t.contains("php_admin_value[session.save_path] = /srv/vhosts/shop.example.org/tmp"));
        assert!(t.contains("php_admin_value[error_log] = /srv/vhosts/shop.example.org/logs/php-fpm-error.log"));
        assert!(t.contains("php_admin_flag[log_errors] = on"));
    }

    #[test]
    fn php_settings_become_pool_settings() {
        let mut m = sample();
        m.fpm.php_value.insert("memory_limit".into(), "256M".into());
        m.fpm.php_flag.insert("display_errors".into(), "off".into());
        let t = render(&m, "8.3", "/srv/vhosts");
        assert!(t.contains("php_value[memory_limit] = 256M\nphp_flag[display_errors] = off\n"));
    }

    #[test]
    fn finds_a_pool_by_its_socket() {
        let d = std::env::temp_dir().join(format!("larry-pools-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join("a.conf"), "[a]\nuser = php-a\nlisten = /run/php/a.sock\n").unwrap();
        std::fs::write(d.join("b.conf"), "[b]\n; listen = /run/php/b.sock\nuser = php-b ; c\ngroup = grp\nlisten = /run/php/b.sock\n").unwrap();
        let (f, u, g) = find_pool_by_socket(&[&d], "/run/php/b.sock").unwrap();
        assert!(f.ends_with("b.conf") && u == "php-b" && g.as_deref() == Some("grp"));
        assert!(find_pool_by_socket(&[&d], "/run/php/none.sock").is_none());
        let _ = std::fs::remove_dir_all(&d);
    }
}
