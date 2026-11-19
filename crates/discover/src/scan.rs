//! One read-only pass over a site's tree: size, file count, orphaned GIDs,
//! `.htaccess` PHP directives, and hits for the old absolute path.

use crate::apache::php_directives;
use std::collections::BTreeSet;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

#[derive(Debug, Default)]
pub struct SiteScan {
    pub bytes: u64,
    pub files: u64,
    pub gids: BTreeSet<u32>,
    /// (kind, name, value, relative file)
    pub htaccess_php: Vec<(String, String, String, String)>,
    /// (relative file, occurrences of an old path)
    pub old_path_hits: Vec<(String, u64)>,
}

const PHP_EXT: [&str; 3] = ["php", "inc", "phtml"];

/// Symlinks are never followed. `excludes` are nested vhost trees that belong to another site.
pub fn scan_site(root: &Path, docroot: &Path, excludes: &[PathBuf], needles: &[String]) -> SiteScan {
    let mut out = SiteScan::default();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(rd) = fs::read_dir(&dir) else { continue };
        for e in rd.flatten() {
            let Ok(ft) = e.file_type() else { continue };
            let path = e.path();
            if ft.is_symlink() {
                continue;
            }
            if ft.is_dir() {
                if !excludes.iter().any(|x| x == &path) {
                    stack.push(path);
                }
                continue;
            }
            if !ft.is_file() {
                continue;
            }
            let Ok(meta) = e.metadata() else { continue };
            out.bytes += meta.len();
            out.files += 1;
            out.gids.insert(meta.gid());
            let rel = path.strip_prefix(root).unwrap_or(&path).display().to_string();
            let name = e.file_name().to_string_lossy().into_owned();

            if name == ".htaccess" && path.starts_with(docroot) && meta.len() < 1_000_000 {
                if let Ok(b) = fs::read(&path) {
                    for (k, n, v) in php_directives(&String::from_utf8_lossy(&b)) {
                        out.htaccess_php.push((k, n, v, rel.clone()));
                    }
                }
            }
            if !needles.is_empty() && meta.len() < 5_000_000 {
                let ext = path.extension().map(|x| x.to_string_lossy().to_ascii_lowercase()).unwrap_or_default();
                if PHP_EXT.contains(&ext.as_str()) {
                    if let Ok(b) = fs::read(&path) {
                        let text = String::from_utf8_lossy(&b);
                        let n: usize = needles.iter().map(|x| text.matches(x.as_str()).count()).sum();
                        if n > 0 {
                            out.old_path_hits.push((rel, n as u64));
                        }
                    }
                }
            }
        }
    }
    out.htaccess_php.sort();
    out.old_path_hits.sort();
    out
}

/// GIDs defined in a group file (`/etc/group`); used to find orphaned GIDs on the source.
pub fn known_gids(group_file: &Path) -> BTreeSet<u32> {
    fs::read_to_string(group_file)
        .unwrap_or_default()
        .lines()
        .filter_map(|l| l.split(':').nth(2)?.parse().ok())
        .collect()
}
