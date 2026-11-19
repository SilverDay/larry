//! Apache vhost files: render the HTTP and HTTPS vhosts, read an existing vhost.

use crate::manifest::Manifest;
use crate::pool;
use regex::Regex;

pub fn conf_name(domain: &str) -> String {
    format!("{domain}.conf")
}

/// One vhost file holding the port-80 vhost and, when the site has a certificate, the 443 one.
pub fn render(m: &Manifest, php_version: &str, vhost_base: &str) -> String {
    let root = format!("{}/{}", vhost_base.trim_end_matches('/'), m.domain);
    let doc = format!("{root}/{}", m.docroot);
    let logs = format!("{root}/logs");
    let sock = pool::socket_path(php_version, &pool::pool_name(m));
    let alias = if m.aliases.is_empty() { String::new() } else { format!("    ServerAlias {}\n", m.aliases.join(" ")) };
    let body = |extra: &str| {
        let mut s = format!("    ServerName {}\n{alias}    DocumentRoot {doc}\n\n", m.domain);
        s.push_str(&format!("    ErrorLog {logs}/error.log\n    CustomLog {logs}/access.log combined\n"));
        s.push_str(extra);
        if m.php {
            s.push_str(&format!("\n    <FilesMatch \"\\.php$\">\n        SetHandler \"proxy:unix:{sock}|fcgi://localhost/\"\n    </FilesMatch>\n"));
        }
        s.push_str(&format!(
            "\n    <Directory {doc}>\n        Options -Indexes +FollowSymLinks\n        AllowOverride All\n        Require all granted\n    </Directory>\n"
        ));
        s
    };
    let mut out = format!("# written by larry for {}\n", m.domain);
    if let Some(cert) = m.tls.first() {
        out.push_str(&format!("<VirtualHost *:80>\n    ServerName {}\n{alias}    Redirect permanent / https://{}/\n</VirtualHost>\n\n", m.domain, m.domain));
        let ssl = format!(
            "\n    SSLEngine on\n    SSLCertificateFile /etc/letsencrypt/live/{cert}/fullchain.pem\n    SSLCertificateKeyFile /etc/letsencrypt/live/{cert}/privkey.pem\n"
        );
        out.push_str(&format!("<VirtualHost *:443>\n{}</VirtualHost>\n", body(&ssl)));
    } else {
        out.push_str(&format!("<VirtualHost *:80>\n{}</VirtualHost>\n", body("")));
    }
    out
}

/// Every `DocumentRoot` in the text, trailing slashes removed, unique and sorted.
pub fn docroots_of(text: &str) -> Vec<String> {
    let re = Regex::new(r#"(?im)^\s*DocumentRoot\s+"?([^"\s]+)"?"#).unwrap();
    let mut v: Vec<String> = re.captures_iter(text).map(|c| c[1].trim_end_matches('/').to_string()).collect();
    v.sort();
    v.dedup();
    v
}

/// Every `proxy:unix:` socket named in the text.
pub fn proxy_sockets(text: &str) -> Vec<String> {
    let re = Regex::new(r#"proxy:unix:([^|"\s]+)"#).unwrap();
    let mut v: Vec<String> = re.captures_iter(text).map(|c| c[1].to_string()).collect();
    v.sort();
    v.dedup();
    v
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::sample;

    #[test]
    fn http_only_when_there_is_no_certificate() {
        let mut m = sample();
        m.tls.clear();
        let t = render(&m, "8.3", "/srv/vhosts");
        assert!(t.contains("<VirtualHost *:80>") && !t.contains("443") && !t.contains("SSLEngine"));
        assert!(t.contains("ServerAlias www.shop.example.org"));
        assert!(t.contains("DocumentRoot /srv/vhosts/shop.example.org/public"));
        assert!(t.contains("proxy:unix:/run/php/php8.3-fpm-shop-example-org.sock|fcgi://localhost/"));
    }

    #[test]
    fn https_vhost_uses_the_copied_certificate_and_http_redirects() {
        let t = render(&sample(), "8.3", "/srv/vhosts");
        assert!(t.contains("Redirect permanent / https://shop.example.org/"));
        assert!(t.contains("SSLCertificateFile /etc/letsencrypt/live/shop.example.org/fullchain.pem"));
        assert!(t.contains("<VirtualHost *:443>"));
    }

    #[test]
    fn static_site_has_no_php_handler() {
        let mut m = sample();
        m.php = false;
        assert!(!render(&m, "8.3", "/srv/vhosts").contains("SetHandler"));
    }

    #[test]
    fn reads_an_existing_vhost() {
        let t = "<VirtualHost *:443>\n  DocumentRoot \"/srv/vhosts/a/public/\"\n SetHandler \"proxy:unix:/run/php/x.sock|fcgi://localhost/\"\n</VirtualHost>";
        assert_eq!(docroots_of(t), vec!["/srv/vhosts/a/public"]);
        assert_eq!(proxy_sockets(t), vec!["/run/php/x.sock"]);
    }
}
