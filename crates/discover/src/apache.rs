//! Parsing `apache2ctl -S` and vhost config text (ported from scan-vhosts.sh).

use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq)]
pub struct ConfRef {
    pub path: String,
    pub line: usize,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct VhostEntry {
    pub name: String,
    pub aliases: Vec<String>,
    pub confs: Vec<ConfRef>,
}

/// Both forms `apache2ctl -S` prints:
///   `port 443 namevhost NAME (FILE:LINE)`   name-based
///   `1.2.3.4:80   NAME (FILE:LINE)`          IP-based / default vhost
/// Matching only the first silently drops IP-based vhosts.
pub fn parse_apache_s(text: &str) -> Vec<VhostEntry> {
    let mut map: BTreeMap<String, VhostEntry> = BTreeMap::new();
    let mut current: Option<String> = None;
    for line in text.lines() {
        let line = line.trim_end_matches('\r');
        let caps = re!(r"(?:namevhost|default server)\s+(\S+)\s+\((.+):(\d+)\)")
            .captures(line)
            .or_else(|| re!(r"^\S+:[0-9*]+\s+(\S+)\s+\((.+):(\d+)\)\s*$").captures(line));
        if let Some(c) = caps {
            let name = c[1].to_string();
            let cref = ConfRef { path: c[2].to_string(), line: c[3].parse().unwrap_or(0) };
            let e = map.entry(name.clone()).or_insert_with(|| VhostEntry { name: name.clone(), ..Default::default() });
            if !e.confs.contains(&cref) {
                e.confs.push(cref);
            }
            current = Some(name);
        } else if let Some(c) = re!(r"^\s+alias\s+(\S+)").captures(line) {
            if let Some(cur) = &current {
                let e = map.get_mut(cur).expect("current vhost exists");
                let a = c[1].to_string();
                if !e.aliases.contains(&a) {
                    e.aliases.push(a);
                }
            }
        }
    }
    map.into_values().collect()
}

/// The `<VirtualHost>` block that starts at `line` (as `apache2ctl -S` reports it),
/// so a file holding several vhosts only contributes its own block. Falls back to the whole file.
pub fn vhost_block(text: &str, line: usize) -> String {
    let lines: Vec<&str> = text.lines().collect();
    if line >= 1 && line <= lines.len() && lines[line - 1].to_ascii_lowercase().contains("<virtualhost") {
        let mut out = Vec::new();
        for l in &lines[line - 1..] {
            out.push(*l);
            if l.trim().to_ascii_lowercase().starts_with("</virtualhost") {
                break;
            }
        }
        return out.join("\n");
    }
    text.to_string()
}

#[derive(Debug, Default, PartialEq)]
pub struct ConfInfo {
    pub docroots: Vec<String>,
    pub ssl: bool,
    pub proxy_sockets: Vec<String>,
    /// (kind, name, value)
    pub php: Vec<(String, String, String)>,
}

pub fn parse_conf(text: &str) -> ConfInfo {
    let mut info = ConfInfo::default();
    for c in re!(r"(?im)^[ \t]*DocumentRoot[ \t]+(.+?)[ \t\r]*$").captures_iter(text) {
        info.docroots.push(clean_path(&c[1]));
    }
    info.ssl = re!(r"(?im)^[ \t]*(SSLEngine[ \t]+on|SSLCertificateFile)|<VirtualHost[^>]*:443").is_match(text);
    for c in re!(r#"proxy:unix:([^|\s"]+)\|"#).captures_iter(text) {
        info.proxy_sockets.push(c[1].to_string());
    }
    info.php = php_directives(text);
    info
}

/// `php_value` / `php_flag` / `php_admin_*` lines (vhosts and .htaccess).
pub fn php_directives(text: &str) -> Vec<(String, String, String)> {
    re!(r"(?im)^[ \t]*(php_value|php_flag|php_admin_value|php_admin_flag)[ \t]+(\S+)[ \t]+(.*?)[ \t\r]*$")
        .captures_iter(text)
        .map(|c| (c[1].to_ascii_lowercase(), c[2].to_string(), c[3].trim_matches('"').to_string()))
        .collect()
}

fn clean_path(p: &str) -> String {
    let p = p.trim().trim_matches('"');
    let t = p.trim_end_matches('/');
    if t.is_empty() {
        p.to_string()
    } else {
        t.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const S: &str = "\
VirtualHost configuration:
*:443                  is a NameVirtualHost
         default server shop.example.org (/etc/apache2/sites-enabled/shop.conf:1)
         port 443 namevhost shop.example.org (/etc/apache2/sites-enabled/shop.conf:1)
                 alias www.shop.example.org
*:80                   is a NameVirtualHost
         port 80 namevhost shop.example.org (/etc/apache2/sites-enabled/shop.conf:20)
192.0.2.7:80           ip.example.org (/etc/apache2/sites-enabled/ip.conf:3)
                 alias www.ip.example.org
";

    #[test]
    fn both_forms_are_found_and_merged() {
        let v = parse_apache_s(S);
        let names: Vec<_> = v.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, ["ip.example.org", "shop.example.org"]);
        let shop = &v[1];
        assert_eq!(shop.confs.len(), 2);
        assert_eq!(shop.confs[1].line, 20);
        assert_eq!(shop.aliases, ["www.shop.example.org"]);
        assert_eq!(v[0].aliases, ["www.ip.example.org"]);
    }

    #[test]
    fn block_is_cut_at_the_reported_line() {
        let t = "<VirtualHost *:80>\n DocumentRoot /a\n</VirtualHost>\n<VirtualHost *:80>\n DocumentRoot /b/\n</VirtualHost>\n";
        assert_eq!(parse_conf(&vhost_block(t, 4)).docroots, ["/b"]);
        assert_eq!(parse_conf(&vhost_block(t, 1)).docroots, ["/a"]);
        assert_eq!(parse_conf(&vhost_block(t, 99)).docroots, ["/a", "/b"]);
    }

    #[test]
    fn conf_details() {
        let c = parse_conf(
            "<VirtualHost *:443>\r\n  DocumentRoot \"/srv/x/httpdocs/\"\r\n  SSLCertificateFile /c\r\n\
             # DocumentRoot /ignored\r\n  <FilesMatch>\r\n SetHandler \"proxy:unix:/run/php/a.sock|fcgi://localhost\"\r\n\
             php_admin_value open_basedir \"/srv/x\"\r\n</VirtualHost>",
        );
        assert_eq!(c.docroots, ["/srv/x/httpdocs"]);
        assert!(c.ssl);
        assert_eq!(c.proxy_sockets, ["/run/php/a.sock"]);
        assert_eq!(c.php, [("php_admin_value".to_string(), "open_basedir".to_string(), "/srv/x".to_string())]);
    }
}
