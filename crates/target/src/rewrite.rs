//! Opt-in path rewriting in PHP files (`rewrite_paths = true`): the exact old vhost and docroot
//! paths become the new ones. A hit inside a PHP serialized string (`s:<len>:"…"`) is skipped and
//! reported, because changing its length would corrupt the value.

use regex::Regex;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

pub const PHP_EXTENSIONS: &[&str] = &["php", "inc", "phtml"];
const MAX_FILE: u64 = 16 * 1024 * 1024;

#[derive(Debug, Default, PartialEq)]
pub struct Rewritten {
    pub content: String,
    pub replaced: usize,
    pub skipped_serialized: usize,
    /// (1-based line, line before, line after)
    pub changes: Vec<(usize, String, String)>,
}

fn path_char(c: u8) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, b'_' | b'-' | b'.' | b'/')
}

/// Byte ranges of the contents of every `s:<len>:"…"` string.
fn serialized_spans(text: &str) -> Vec<(usize, usize)> {
    let re = Regex::new(r#"s:(\d+):""#).unwrap();
    let mut spans = vec![];
    for c in re.captures_iter(text) {
        let whole = c.get(0).unwrap();
        let Ok(len) = c[1].parse::<usize>() else { continue };
        let start = whole.end();
        let end = start + len;
        if end <= text.len() && text.as_bytes().get(end) == Some(&b'"') {
            spans.push((start, end));
        }
    }
    spans
}

/// Replace every exact occurrence of an old path (longest first, on path boundaries).
pub fn rewrite(text: &str, pairs: &[(String, String)]) -> Rewritten {
    let mut pairs: Vec<&(String, String)> = pairs.iter().filter(|(o, n)| !o.is_empty() && o != n).collect();
    pairs.sort_by_key(|(o, _)| std::cmp::Reverse(o.len()));
    let spans = serialized_spans(text);
    let bytes = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut r = Rewritten::default();
    let (mut i, mut line, mut line_start) = (0usize, 1usize, 0usize);
    let mut line_changed = false;
    let mut before_lines: Vec<(usize, usize)> = vec![]; // lines (number, start) that changed
    while i < bytes.len() {
        let mut hit = None;
        if i == 0 || !path_char(bytes[i - 1]) {
            for (old, new) in &pairs {
                if bytes[i..].starts_with(old.as_bytes())
                    && bytes.get(i + old.len()).is_none_or(|c| !matches!(c, b'_' | b'-' | b'.') && !c.is_ascii_alphanumeric())
                {
                    hit = Some((old.len(), new));
                    break;
                }
            }
        }
        match hit {
            Some((len, new)) => {
                if spans.iter().any(|(s, e)| i >= *s && i < *e) {
                    r.skipped_serialized += 1;
                    out.push_str(&text[i..i + len]);
                } else {
                    r.replaced += 1;
                    out.push_str(new);
                    if !line_changed {
                        line_changed = true;
                        before_lines.push((line, line_start));
                    }
                }
                i += len;
            }
            None => {
                let ch = text[i..].chars().next().unwrap();
                out.push(ch);
                if ch == '\n' {
                    line += 1;
                    line_start = i + 1;
                    line_changed = false;
                }
                i += ch.len_utf8();
            }
        }
    }
    let new_lines: Vec<&str> = out.lines().collect();
    let old_lines: Vec<&str> = text.lines().collect();
    for (n, _) in before_lines {
        r.changes.push((n, old_lines[n - 1].to_string(), new_lines.get(n - 1).copied().unwrap_or("").to_string()));
    }
    r.content = out;
    r
}

#[derive(Debug, Default)]
pub struct TreeReport {
    pub changed: Vec<(PathBuf, Rewritten)>,
    /// Files with hits only inside serialized strings (nothing changed there), as `path: count`.
    pub skipped: Vec<(PathBuf, usize)>,
    pub unreadable: Vec<PathBuf>,
}

fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(rd) = std::fs::read_dir(dir) else { return };
    let mut entries: Vec<_> = rd.flatten().collect();
    entries.sort_by_key(|e| e.file_name());
    for e in entries {
        let p = e.path();
        match e.file_type() {
            Ok(t) if t.is_dir() => walk(&p, out),
            Ok(t) if t.is_file() && p.extension().and_then(|x| x.to_str()).is_some_and(|x| PHP_EXTENSIONS.contains(&x.to_ascii_lowercase().as_str())) => {
                out.push(p)
            }
            _ => {} // symlinks are never followed or written through
        }
    }
}

/// Rewrite below `root`. Each changed file is first copied to `backup_dir/<relative path>`; the new
/// content is written next to it and renamed over it, keeping owner and mode. `dry_run` only reports.
pub fn rewrite_tree(root: &Path, pairs: &[(String, String)], backup_dir: &Path, dry_run: bool) -> Result<TreeReport, String> {
    let mut files = vec![];
    walk(root, &mut files);
    let mut rep = TreeReport::default();
    for f in files {
        let meta = std::fs::symlink_metadata(&f).map_err(|e| format!("{}: {e}", f.display()))?;
        if meta.len() > MAX_FILE {
            rep.unreadable.push(f);
            continue;
        }
        let Ok(text) = std::fs::read_to_string(&f) else {
            rep.unreadable.push(f);
            continue;
        };
        let r = rewrite(&text, pairs);
        if r.replaced == 0 {
            if r.skipped_serialized > 0 {
                rep.skipped.push((f, r.skipped_serialized));
            }
            continue;
        }
        if !dry_run {
            let rel = f.strip_prefix(root).unwrap();
            let bak = backup_dir.join(rel);
            if let Some(p) = bak.parent() {
                std::fs::create_dir_all(p).map_err(|e| format!("{}: {e}", p.display()))?;
            }
            std::fs::copy(&f, &bak).map_err(|e| format!("backup of {}: {e}", f.display()))?;
            let part = f.with_extension(format!("{}.larry-part", f.extension().and_then(|x| x.to_str()).unwrap_or("")));
            std::fs::write(&part, &r.content).map_err(|e| format!("{}: {e}", part.display()))?;
            std::fs::set_permissions(&part, std::fs::Permissions::from_mode(meta.mode() & 0o7777)).map_err(|e| e.to_string())?;
            std::os::unix::fs::lchown(&part, Some(meta.uid()), Some(meta.gid())).map_err(|e| format!("{}: {e}", part.display()))?;
            std::fs::rename(&part, &f).map_err(|e| format!("{}: {e}", f.display()))?;
        }
        if r.skipped_serialized > 0 {
            rep.skipped.push((f.clone(), r.skipped_serialized));
        }
        rep.changed.push((f, r));
    }
    Ok(rep)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p() -> Vec<(String, String)> {
        vec![("/var/www/shop".into(), "/srv/vhosts/shop.example.org".into()), ("/var/www/shop/httpdocs".into(), "/srv/vhosts/shop.example.org/public".into())]
    }

    #[test]
    fn longest_old_path_wins_and_only_exact_paths_change() {
        let src = "<?php\n$a = '/var/www/shop/httpdocs/x';\n$b = \"/var/www/shop/logs\";\n$c = '/var/www/shop2/x'; $d = '/opt/var/www/shop';\n";
        let r = rewrite(src, &p());
        assert_eq!(r.replaced, 2);
        assert!(r.content.contains("'/srv/vhosts/shop.example.org/public/x'"));
        assert!(r.content.contains("\"/srv/vhosts/shop.example.org/logs\""));
        assert!(r.content.contains("'/var/www/shop2/x'") && r.content.contains("'/opt/var/www/shop'"));
        assert_eq!(r.changes.iter().map(|c| c.0).collect::<Vec<_>>(), vec![2, 3]);
    }

    #[test]
    fn serialized_strings_are_skipped_not_corrupted() {
        let s = format!("a:1:{{s:4:\"path\";s:{}:\"/var/www/shop/x\";}}", "/var/www/shop/x".len());
        let src = format!("<?php\n$x = unserialize('{s}');\n$y = '/var/www/shop';\n");
        let r = rewrite(&src, &p());
        assert_eq!((r.replaced, r.skipped_serialized), (1, 1));
        assert!(r.content.contains(&s), "the serialized value is untouched");
        assert!(r.content.contains("$y = '/srv/vhosts/shop.example.org';"));
    }

    #[test]
    fn tree_rewrite_backs_up_and_keeps_mode_and_skips_other_files() {
        let d = std::env::temp_dir().join(format!("larry-rw-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        let (root, bak) = (d.join("root"), d.join("bak"));
        std::fs::create_dir_all(root.join("sub")).unwrap();
        std::fs::write(root.join("sub/a.php"), "<?php $p='/var/www/shop';").unwrap();
        std::fs::write(root.join("notes.txt"), "/var/www/shop").unwrap();
        std::fs::set_permissions(root.join("sub/a.php"), std::fs::Permissions::from_mode(0o640)).unwrap();
        let dry = rewrite_tree(&root, &p(), &bak, true).unwrap();
        assert_eq!(dry.changed.len(), 1);
        assert!(std::fs::read_to_string(root.join("sub/a.php")).unwrap().contains("/var/www/shop") && !bak.exists());
        let rep = rewrite_tree(&root, &p(), &bak, false).unwrap();
        assert_eq!(rep.changed.len(), 1);
        assert_eq!(std::fs::read_to_string(root.join("sub/a.php")).unwrap(), "<?php $p='/srv/vhosts/shop.example.org';");
        assert_eq!(std::fs::read_to_string(bak.join("sub/a.php")).unwrap(), "<?php $p='/var/www/shop';");
        assert_eq!(std::fs::metadata(root.join("sub/a.php")).unwrap().permissions().mode() & 0o777, 0o640);
        assert_eq!(std::fs::read_to_string(root.join("notes.txt")).unwrap(), "/var/www/shop", "only PHP files");
        let _ = std::fs::remove_dir_all(&d);
    }
}
