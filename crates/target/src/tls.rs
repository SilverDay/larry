//! Let's Encrypt material: which certificates a vhost uses, and recreating certbot's
//! `live/` symlinks from a copied `archive/`.

use regex::Regex;
use std::path::{Path, PathBuf};

/// Lineage names from `SSLCertificateFile /etc/letsencrypt/live/<name>/…` lines.
pub fn lineages_in(conf: &str) -> Vec<String> {
    let re = Regex::new(r"(?im)^\s*SSLCertificate(?:Key)?File\s+/etc/letsencrypt/live/([A-Za-z0-9._-]+)/").unwrap();
    let mut v: Vec<String> = re.captures_iter(conf).map(|c| c[1].to_string()).collect();
    v.sort();
    v.dedup();
    v
}

/// For `archive/<name>/` holding `cert1.pem, cert2.pem, privkey2.pem…`: the newest number per kind.
pub fn latest_files(archive: &Path) -> Result<Vec<(String, PathBuf)>, String> {
    let re = Regex::new(r"^(cert|chain|fullchain|privkey)(\d+)\.pem$").unwrap();
    let mut best: std::collections::BTreeMap<String, (u64, PathBuf)> = Default::default();
    let rd = std::fs::read_dir(archive).map_err(|e| format!("{}: {e}", archive.display()))?;
    for e in rd.flatten() {
        let name = e.file_name().to_string_lossy().to_string();
        if let Some(c) = re.captures(&name) {
            let n: u64 = c[2].parse().unwrap_or(0);
            let kind = c[1].to_string();
            if best.get(&kind).is_none_or(|(m, _)| n > *m) {
                best.insert(kind, (n, e.path()));
            }
        }
    }
    for k in ["cert", "chain", "fullchain", "privkey"] {
        if !best.contains_key(k) {
            return Err(format!("{}: no {k}N.pem", archive.display()));
        }
    }
    Ok(best.into_iter().map(|(k, (_, p))| (format!("{k}.pem"), p)).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lineage_names_from_a_vhost() {
        let c = "SSLCertificateFile /etc/letsencrypt/live/a.example.org/fullchain.pem\nSSLCertificateKeyFile /etc/letsencrypt/live/a.example.org/privkey.pem\n  SSLCertificateFile /etc/ssl/other.pem\n";
        assert_eq!(lineages_in(c), vec!["a.example.org"]);
    }

    #[test]
    fn newest_numbered_files_are_chosen() {
        let d = std::env::temp_dir().join(format!("larry-tls-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        for k in ["cert", "chain", "fullchain", "privkey"] {
            for n in [1, 2, 10] {
                std::fs::write(d.join(format!("{k}{n}.pem")), "x").unwrap();
            }
        }
        let l = latest_files(&d).unwrap();
        assert!(l.iter().all(|(_, p)| p.to_string_lossy().ends_with("10.pem")) && l.len() == 4);
        std::fs::remove_file(d.join("privkey1.pem")).unwrap();
        std::fs::remove_file(d.join("privkey2.pem")).unwrap();
        std::fs::remove_file(d.join("privkey10.pem")).unwrap();
        assert!(latest_files(&d).is_err());
        let _ = std::fs::remove_dir_all(&d);
    }
}
