//! How a site sends mail, from its own files: PHP `mail()` (needs a local MTA on the target) or SMTP
//! settings (carry over, but the target must be allowed to reach that server). Read-only, bounded.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

const PRUNE: [&str; 8] = ["vendor", "node_modules", ".git", "cache", "tmp", "logs", "uploads", "backup"];
const MAX_FILE: u64 = 1_000_000;
const MAX_FILES: usize = 5000;

#[derive(Debug, Default, PartialEq)]
pub struct MailUse {
    /// Files calling PHP `mail()`.
    pub php_mail: Vec<String>,
    /// SMTP hosts named in config files, with the file.
    pub smtp: Vec<(String, String)>,
    /// Mail libraries named in composer.json.
    pub libraries: BTreeSet<String>,
}

impl MailUse {
    pub fn is_empty(&self) -> bool {
        self.php_mail.is_empty() && self.smtp.is_empty() && self.libraries.is_empty()
    }
    pub fn needs_local_mta(&self) -> bool {
        !self.php_mail.is_empty()
    }
    pub fn summary(&self) -> String {
        let mut p = vec![];
        if !self.php_mail.is_empty() {
            p.push(format!("PHP mail() in {} file(s), e.g. {} (needs a working MTA on the target)", self.php_mail.len(), self.php_mail[0]));
        }
        for (h, f) in &self.smtp {
            p.push(format!("SMTP via {h} ({f}); the target must be allowed to reach it"));
        }
        if !self.libraries.is_empty() {
            p.push(format!("mail library: {}", self.libraries.iter().cloned().collect::<Vec<_>>().join(", ")));
        }
        p.join("; ")
    }
}

/// `text` of one file. `name` decides which signals apply.
pub fn scan_text(name: &str, rel: &str, text: &str, out: &mut MailUse) {
    let lower = name.to_ascii_lowercase();
    if lower.ends_with(".php") || lower.ends_with(".inc") || lower.ends_with(".phtml") {
        // `mail(` as a function call, not `->mail(`, `::mail(`, `$mail(` or `function mail(`
        if re!(r"(?m)(^|[^>\w:$])mail\s*\(").is_match(text) && !re!(r"function\s+mail\s*\(").is_match(text) && out.php_mail.len() < 50 {
            out.php_mail.push(rel.to_string());
        }
        for c in re!(r#"(?i)['"](?:SMTP_HOST|smtp_host|MAIL_HOST|smtphost)['"]\s*(?:,|=>)\s*['"]([A-Za-z0-9._-]+)['"]"#).captures_iter(text) {
            out.smtp.push((c[1].to_string(), rel.to_string()));
        }
    } else if lower == ".env" || lower.starts_with(".env.") {
        for c in re!(r#"(?m)^\s*(?:export\s+)?(?:MAIL_HOST|SMTP_HOST|MAILER_HOST)\s*=\s*['"]?([A-Za-z0-9._-]+)"#).captures_iter(text) {
            out.smtp.push((c[1].to_string(), rel.to_string()));
        }
        if re!(r"(?m)^\s*MAIL_(?:MAILER|DRIVER)\s*=\s*['\x22]?sendmail").is_match(text) {
            out.php_mail.push(rel.to_string());
        }
    } else if lower == "composer.json" {
        for c in re!(r#"(?i)"((?:phpmailer/phpmailer|swiftmailer/swiftmailer|symfony/mailer|symfony/swiftmailer-bundle))""#).captures_iter(text) {
            out.libraries.insert(c[1].to_lowercase());
        }
    }
    // localhost is "local MTA", not an external SMTP server
    out.smtp.retain(|(h, _)| !matches!(h.as_str(), "localhost" | "127.0.0.1"));
}

pub fn scan(root: &Path, excludes: &[PathBuf]) -> MailUse {
    let mut out = MailUse::default();
    let mut stack = vec![root.to_path_buf()];
    let mut seen = 0;
    while let Some(dir) = stack.pop() {
        let Ok(rd) = fs::read_dir(&dir) else { continue };
        let mut es: Vec<_> = rd.flatten().collect();
        es.sort_by_key(|e| e.file_name());
        for e in es {
            let Ok(ft) = e.file_type() else { continue };
            let p = e.path();
            let name = e.file_name().to_string_lossy().to_string();
            if ft.is_dir() && !ft.is_symlink() {
                if !PRUNE.contains(&name.as_str()) && !excludes.contains(&p) {
                    stack.push(p);
                }
            } else if ft.is_file() {
                seen += 1;
                if seen > MAX_FILES {
                    return out;
                }
                if e.metadata().map(|m| m.len() > MAX_FILE).unwrap_or(true) {
                    continue;
                }
                if let Ok(t) = fs::read_to_string(&p) {
                    scan_text(&name, &p.strip_prefix(root).unwrap_or(&p).display().to_string(), &t, &mut out);
                }
            }
        }
    }
    out.smtp.sort();
    out.smtp.dedup();
    out.php_mail.sort();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn one(name: &str, text: &str) -> MailUse {
        let mut m = MailUse::default();
        scan_text(name, name, text, &mut m);
        m
    }

    #[test]
    fn php_mail_calls_but_not_methods() {
        assert_eq!(one("a.php", "<?php mail($to, $s, $b);").php_mail, vec!["a.php"]);
        assert_eq!(one("a.php", "<?php if (@mail('x','y','z')) {}").php_mail.len(), 1);
        assert!(one("a.php", "<?php $m->mail($x); Foo::mail(1); function mail($a) {}").php_mail.is_empty());
    }

    #[test]
    fn smtp_settings_and_libraries() {
        assert_eq!(one(".env", "MAIL_HOST=smtp.example.net\nMAIL_PORT=587\n").smtp[0].0, "smtp.example.net");
        assert!(one(".env", "MAIL_HOST=localhost\n").smtp.is_empty());
        assert_eq!(one("wp-config.php", "define('SMTP_HOST', 'mail.example.org');").smtp[0].0, "mail.example.org");
        assert!(one(".env.production", "MAIL_MAILER=sendmail").needs_local_mta());
        assert!(one("composer.json", r#"{"require":{"phpmailer/phpmailer":"^6"}}"#).libraries.contains("phpmailer/phpmailer"));
    }

    #[test]
    fn scan_skips_vendor_and_nested_trees() {
        let d = std::env::temp_dir().join(format!("larry-mail-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        for s in ["vendor/x", "blog", "app"] {
            fs::create_dir_all(d.join(s)).unwrap();
        }
        fs::write(d.join("vendor/x/a.php"), "<?php mail(1,2,3);").unwrap();
        fs::write(d.join("blog/b.php"), "<?php mail(1,2,3);").unwrap();
        fs::write(d.join("app/c.php"), "<?php mail(1,2,3);").unwrap();
        let m = scan(&d, &[d.join("blog")]);
        assert_eq!(m.php_mail, vec!["app/c.php"]);
        assert!(m.summary().contains("needs a working MTA"));
        let _ = fs::remove_dir_all(&d);
    }
}
