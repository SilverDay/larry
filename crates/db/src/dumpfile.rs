//! The dump file format: gzip SQL whose first line names domain, database, source and time,
//! plus a `.sha256` sidecar that records the bare file name (so it verifies from any directory).

use flate2::read::GzDecoder;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs::File;
use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq)]
pub struct Header {
    pub domain: String,
    pub db: String,
    pub source: Option<String>,
    pub dumped_at: Option<String>,
}

pub fn header_line(domain: &str, db: &str, source: &str, dumped_at: &str) -> String {
    format!("-- migration-db: domain={domain} db={db} source={source} dumped_at={dumped_at}")
}

pub fn parse_header(line: &str) -> Option<Header> {
    let c = re!(r"^-- migration-db: domain=([A-Za-z0-9.-]+) db=([A-Za-z0-9_-]+)(?: source=(\S+))?(?: dumped_at=(\S+))?\s*$")
        .captures(line.trim_end_matches('\r'))?;
    Some(Header {
        domain: c[1].into(),
        db: c[2].into(),
        source: c.get(3).map(|m| m.as_str().into()),
        dumped_at: c.get(4).map(|m| m.as_str().into()),
    })
}

pub fn sha256_file(path: &Path) -> Result<String, String> {
    let mut f = File::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 1 << 16];
    loop {
        let n = f.read(&mut buf).map_err(|e| format!("{}: {e}", path.display()))?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(h.finalize().iter().map(|b| format!("{b:02x}")).collect())
}

pub fn sidecar(path: &Path) -> PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(".sha256");
    PathBuf::from(s)
}

/// Write `<hash>  <bare file name>` next to the file; returns the hash.
pub fn write_sidecar(path: &Path) -> Result<String, String> {
    let hash = sha256_file(path)?;
    let name = path.file_name().ok_or("no file name")?.to_string_lossy();
    let side = sidecar(path);
    std::fs::write(&side, format!("{hash}  {name}\n")).map_err(|e| format!("{}: {e}", side.display()))?;
    Ok(hash)
}

/// Compare the hash only, so it works from any directory and ignores whatever path the sidecar names.
pub fn verify_checksum(path: &Path) -> Result<String, String> {
    let side = sidecar(path);
    let text = std::fs::read_to_string(&side).map_err(|_| {
        format!("no {} next to it; refusing to use an unverified file", side.file_name().unwrap_or_default().to_string_lossy())
    })?;
    let expected = text.split_whitespace().next().unwrap_or("").to_ascii_lowercase();
    if expected.len() != 64 || !expected.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!("malformed {}", side.display()));
    }
    let actual = sha256_file(path)?;
    if actual != expected {
        return Err(format!("checksum mismatch (expected {expected}, got {actual})"));
    }
    Ok(actual)
}

#[derive(Debug, Default)]
pub struct DumpInfo {
    pub header: Option<Header>,
    /// First line of the file, whatever it is.
    pub first_line: String,
    /// The database the dump switches to (`USE ...`).
    pub use_db: Option<String>,
    pub create_tables: usize,
    /// (user, host) of every `DEFINER=` in views, triggers, routines and events.
    pub definers: BTreeSet<(String, String)>,
}

/// One streaming pass over the decompressed dump.
pub fn inspect(path: &Path) -> Result<DumpInfo, String> {
    let f = File::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut r = BufReader::with_capacity(1 << 16, GzDecoder::new(f));
    let mut info = DumpInfo::default();
    let mut line = Vec::new();
    let mut first = true;
    loop {
        line.clear();
        let n = r.read_until(b'\n', &mut line).map_err(|e| format!("{}: not a readable gzip dump ({e})", path.display()))?;
        if n == 0 {
            break;
        }
        if first {
            info.first_line = String::from_utf8_lossy(&line).trim_end().to_string();
            info.header = parse_header(&info.first_line);
            first = false;
            continue;
        }
        // Row data dominates a dump and never holds any of what we look for.
        if line.starts_with(b"INSERT ") {
            continue;
        }
        if line.starts_with(b"CREATE TABLE ") {
            info.create_tables += 1;
        }
        let text = String::from_utf8_lossy(&line);
        if info.use_db.is_none() {
            if let Some(c) = re!(r"^USE `([^`]+)`;").captures(&text) {
                info.use_db = Some(c[1].into());
            }
        }
        if text.contains("DEFINER=") {
            for c in re!(r"DEFINER=`([^`]+)`@`([^`]+)`").captures_iter(&text) {
                info.definers.insert((c[1].into(), c[2].into()));
            }
        }
    }
    Ok(info)
}

/// Occurrences of `needle` in the decompressed dump (the old absolute path, reported per site).
pub fn count_occurrences(path: &Path, needle: &str) -> Result<u64, String> {
    let n = needle.as_bytes();
    if n.is_empty() {
        return Ok(0);
    }
    let f = File::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut r = GzDecoder::new(f);
    let mut chunk = vec![0u8; 1 << 16];
    let mut buf: Vec<u8> = Vec::new();
    let mut count = 0u64;
    loop {
        let got = r.read(&mut chunk).map_err(|e| format!("{}: {e}", path.display()))?;
        if got == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..got]);
        count += buf.windows(n.len()).filter(|w| *w == n).count() as u64;
        // A match cannot fit inside the last n-1 bytes, so keeping them loses and double-counts nothing.
        let keep = n.len() - 1;
        if buf.len() > keep {
            buf.drain(..buf.len() - keep);
        }
    }
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::{write::GzEncoder, Compression};
    use std::io::Write;

    pub fn gz(dir: &Path, name: &str, text: &str) -> PathBuf {
        std::fs::create_dir_all(dir).unwrap();
        let p = dir.join(name);
        let mut e = GzEncoder::new(File::create(&p).unwrap(), Compression::fast());
        e.write_all(text.as_bytes()).unwrap();
        e.finish().unwrap();
        p
    }

    fn tmp(n: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("larry-dumpfile-{n}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    #[test]
    fn header_round_trip_and_rejects_garbage() {
        let h = parse_header(&header_line("shop.example.org", "shop_db", "src1", "2026-11-19T10:00:00Z")).unwrap();
        assert_eq!((h.domain.as_str(), h.db.as_str(), h.source.as_deref()), ("shop.example.org", "shop_db", Some("src1")));
        assert!(parse_header("-- MySQL dump 10.13").is_none());
        assert!(parse_header("-- migration-db: domain=a;rm db=x").is_none());
        assert!(parse_header("-- migration-db: domain=a.de db=x y").is_none());
    }

    #[test]
    fn checksum_detects_tampering_and_missing_sidecar() {
        let d = tmp("sum");
        let p = gz(&d, "a.db.sql.gz", "x");
        assert!(verify_checksum(&p).is_err(), "no sidecar");
        let h = write_sidecar(&p).unwrap();
        assert_eq!(verify_checksum(&p).unwrap(), h);
        assert!(std::fs::read_to_string(sidecar(&p)).unwrap().ends_with("  a.db.sql.gz\n"), "bare name");
        std::fs::write(sidecar(&p), format!("{}  /some/other/path.gz\n", h)).unwrap();
        assert!(verify_checksum(&p).is_ok(), "path in the sidecar is irrelevant");
        let mut bytes = std::fs::read(&p).unwrap();
        *bytes.last_mut().unwrap() ^= 1;
        std::fs::write(&p, bytes).unwrap();
        assert!(verify_checksum(&p).unwrap_err().contains("mismatch"));
        std::fs::write(sidecar(&p), "nothex  a\n").unwrap();
        assert!(verify_checksum(&p).unwrap_err().contains("malformed"));
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn inspect_finds_use_tables_and_definers() {
        let d = tmp("inspect");
        let text = format!(
            "{}\n-- MySQL dump\nCREATE DATABASE `shop_db`;\nUSE `shop_db`;\nCREATE TABLE `a` (id int);\nINSERT INTO `a` VALUES ('DEFINER=`bogus`@`x`');\nCREATE TABLE `b` (id int);\n/*!50013 DEFINER=`ghost`@`localhost` SQL SECURITY DEFINER */\nCREATE DEFINER=`app`@`%` TRIGGER t BEFORE INSERT ON a FOR EACH ROW SET @x=1;\n",
            header_line("shop.example.org", "shop_db", "src", "2026-11-19T10:00:00Z")
        );
        let p = gz(&d, "x.gz", &text);
        let i = inspect(&p).unwrap();
        assert_eq!(i.header.unwrap().db, "shop_db");
        assert_eq!(i.use_db.as_deref(), Some("shop_db"));
        assert_eq!(i.create_tables, 2);
        let defs: Vec<_> = i.definers.iter().map(|(u, h)| format!("{u}@{h}")).collect();
        assert_eq!(defs, ["app@%", "ghost@localhost"], "INSERT rows are never parsed");
        std::fs::write(d.join("plain.gz"), "not gzip").unwrap();
        assert!(inspect(&d.join("plain.gz")).is_err());
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn counts_needles_across_chunk_boundaries() {
        let d = tmp("count");
        let needle = "/var/www/old.example.org";
        // push the needle across a 64 KiB read boundary at many offsets
        for pad in [65_520usize, 65_530, 65_535, 65_536, 65_540] {
            let text = format!("{}{needle}{}{needle}", "x".repeat(pad), "y".repeat(10));
            let p = gz(&d, "c.gz", &text);
            assert_eq!(count_occurrences(&p, needle).unwrap(), 2, "pad {pad}");
        }
        assert_eq!(count_occurrences(&gz(&d, "e.gz", "nothing here"), needle).unwrap(), 0);
        std::fs::remove_dir_all(&d).unwrap();
    }
}
