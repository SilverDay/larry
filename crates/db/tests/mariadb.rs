//! Integration test against a private, throwaway MariaDB (own datadir, socket only, no network).
//! Skipped when `mariadbd` / `mariadb-install-db` are not installed. It never touches any
//! other database server on the machine.
//!
//! Covers these rows of the spec's regression table:
//!   - a MyISAM database is dumped with --lock-tables, and the general log confirms the lock
//!   - grants survive DROP and CREATE DATABASE: the app user still reads after an import
//!   - DEFINER accounts missing on the target: the import names them
//!   - tampered dumps change nothing

use larry_db::checks::{collations_available, collations_used, ensure_app_user, missing_collations, UserOutcome};
use larry_db::dump::dump_database;
use larry_db::import::{import, ImportOpts};
use larry_db::{DumpMode, MysqlCli, Sql};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

struct Server {
    child: Child,
    dir: PathBuf,
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn have(tool: &str) -> bool {
    larry_transport::find_tool(&[tool]).is_some() || Path::new("/usr/sbin").join(tool).exists()
}

fn cnf(dir: &Path, name: &str, user: &str, password: Option<&str>) -> PathBuf {
    let p = dir.join(name);
    let pw = password.map(|p| format!("password={p}\n")).unwrap_or_default();
    std::fs::write(&p, format!("[client]\nuser={user}\n{pw}socket={}/s.sock\n", dir.display())).unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
    p
}

fn start() -> Option<(Server, MysqlCli)> {
    if !have("mariadbd") || !have("mariadb-install-db") {
        eprintln!("SKIPPED: mariadbd / mariadb-install-db not installed");
        return None;
    }
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("mariadb-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let st = Command::new("mariadb-install-db")
        .args(["--no-defaults", "--auth-root-authentication-method=normal", "--skip-test-db"])
        .arg(format!("--datadir={}/data", dir.display()))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("run mariadb-install-db");
    assert!(st.success(), "mariadb-install-db failed");
    let child = Command::new("mariadbd")
        .args(["--no-defaults", "--skip-networking", "--general-log"])
        .arg(format!("--datadir={}/data", dir.display()))
        .arg(format!("--socket={}/s.sock", dir.display()))
        .arg(format!("--pid-file={}/pid", dir.display()))
        .arg(format!("--log-error={}/err.log", dir.display()))
        .arg(format!("--general-log-file={}/general.log", dir.display()))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("start mariadbd");
    let server = Server { child, dir: dir.clone() };
    let root = MysqlCli::new(cnf(&dir, "root.cnf", "root", None)).unwrap();
    for _ in 0..60 {
        if root.query("SELECT 1").is_ok() {
            return Some((server, root));
        }
        std::thread::sleep(std::time::Duration::from_millis(250));
    }
    panic!("private mariadbd did not come up; see {}/err.log", dir.display());
}

fn general_log_after(dir: &Path, marker: &str) -> String {
    std::thread::sleep(std::time::Duration::from_millis(200));
    let log = std::fs::read_to_string(dir.join("general.log")).unwrap();
    let at = log.rfind(marker).unwrap_or_else(|| panic!("marker {marker} not in general log"));
    log[at..].to_string()
}

#[test]
fn dump_and_import_against_a_real_mariadb() {
    let Some((server, root)) = start() else { return };
    let dir = server.dir.clone();

    root.query(
        "CREATE DATABASE inno_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
         CREATE TABLE inno_db.t (id INT PRIMARY KEY, v VARCHAR(20)) ENGINE=InnoDB;
         INSERT INTO inno_db.t VALUES (1,'one'),(2,'two'),(3,'three');
         CREATE DEFINER=`ghost`@`localhost` VIEW inno_db.v AS SELECT id FROM inno_db.t;
         CREATE DATABASE myisam_db;
         CREATE TABLE myisam_db.m (id INT) ENGINE=MyISAM;
         INSERT INTO myisam_db.m VALUES (1),(2);
         CREATE USER 'app'@'localhost' IDENTIFIED BY 'apw';
         GRANT ALL PRIVILEGES ON inno_db.* TO 'app'@'localhost';",
    )
    .expect("fixture");

    let staging = dir.join("staging");
    larry_transport::ensure_private_dir(&staging).unwrap();
    let now = 1_700_000_000;

    // --- MyISAM is dumped with --lock-tables, InnoDB with --single-transaction (general log confirms)
    root.query("SELECT 'MARK-MYISAM'").unwrap();
    let r = dump_database(&root, "legacy.example.org", "myisam_db", "src1", &staging, now).unwrap();
    assert_eq!(r.mode, DumpMode::LockTables);
    let log = general_log_after(&dir, "MARK-MYISAM");
    assert!(log.contains("LOCK TABLES"), "the general log must show the table lock");
    assert!(!log.contains("WITH CONSISTENT SNAPSHOT"), "no snapshot is taken for a MyISAM database");

    root.query("SELECT 'MARK-INNODB'").unwrap();
    let shop = dump_database(&root, "shop.example.org", "inno_db", "src1", &staging, now).unwrap();
    assert_eq!(shop.mode, DumpMode::SingleTransaction);
    let log = general_log_after(&dir, "MARK-INNODB");
    assert!(log.contains("WITH CONSISTENT SNAPSHOT") && !log.contains("LOCK TABLES `t`"));
    assert!(shop.path.ends_with("shop.example.org.db.sql.gz") && larry_db::dumpfile::verify_checksum(&shop.path).is_ok());
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(std::fs::metadata(&shop.path).unwrap().permissions().mode() & 0o777, 0o600);

    // the dump names its domain, and the old path is searchable at every sync
    let info = larry_db::dumpfile::inspect(&shop.path).unwrap();
    assert_eq!(info.header.as_ref().unwrap().domain, "shop.example.org");
    assert_eq!(info.use_db.as_deref(), Some("inno_db"));
    assert_eq!(info.create_tables, 1);
    assert!(larry_db::dumpfile::count_occurrences(&shop.path, "inno_db").unwrap() > 0);

    // --- the database drifts, then an import restores it; the app user still reads (grants survive)
    root.query("DELETE FROM inno_db.t WHERE id > 1; CREATE TABLE inno_db.extra (x INT);").unwrap();
    let backups = dir.join("backups");
    let rep = import(&root, &shop.path, &ImportOpts { backup_dir: &backups, dry_run: false, now }).unwrap();
    assert!(rep.imported && rep.existed);
    assert_eq!((rep.tables_before, rep.tables_in_dump, rep.tables_after), (2, 1, Some(1)), "`extra` is gone, as on the source");
    assert!(rep.warnings.is_empty(), "{:?}", rep.warnings);
    assert_eq!(rep.missing_definers, ["'ghost'@'localhost'"], "the import names the missing DEFINER account");
    let bak = rep.backup.expect("existing database was backed up first");
    assert!(larry_db::dumpfile::inspect(&bak).is_ok() && std::fs::metadata(&bak).unwrap().len() > 0);
    assert_eq!(root.query("SELECT COUNT(*) FROM inno_db.t").unwrap().trim(), "3");

    let app = MysqlCli::new(cnf(&dir, "app.cnf", "app", Some("apw"))).unwrap();
    assert_eq!(app.query("SELECT COUNT(*) FROM inno_db.t").unwrap().trim(), "3", "app user still reads after the import");

    // --- a tampered dump changes nothing
    let mut bytes = std::fs::read(&shop.path).unwrap();
    let n = bytes.len();
    bytes[n / 2] ^= 0xff;
    std::fs::write(&shop.path, bytes).unwrap();
    root.query("DELETE FROM inno_db.t WHERE id = 3").unwrap();
    let err = import(&root, &shop.path, &ImportOpts { backup_dir: &backups, dry_run: false, now }).unwrap_err();
    assert!(!err.changed, "{err}");
    assert_eq!(root.query("SELECT COUNT(*) FROM inno_db.t").unwrap().trim(), "2");

    // --- a new database: no backup, then the app user is created from the app's own credentials
    let legacy = import(&root, &r.path, &ImportOpts { backup_dir: &backups, dry_run: false, now }).unwrap();
    assert!(legacy.imported && legacy.existed && legacy.backup.is_some());
    root.query("DROP DATABASE myisam_db").unwrap();
    let fresh = import(&root, &r.path, &ImportOpts { backup_dir: &backups, dry_run: false, now }).unwrap();
    assert!(!fresh.existed && fresh.backup.is_none() && fresh.imported);

    assert_eq!(ensure_app_user(&root, "legacy_app", "se'cret\\pw", "myisam_db").unwrap(), UserOutcome::Created);
    let legacy_app = MysqlCli::new(cnf(&dir, "legacy.cnf", "legacy_app", Some("se'cret\\pw"))).unwrap();
    assert_eq!(legacy_app.query("SELECT COUNT(*) FROM myisam_db.m").unwrap().trim(), "2");
    assert!(legacy_app.query("SELECT COUNT(*) FROM inno_db.t").is_err(), "rights on its own database only");
    assert_eq!(ensure_app_user(&root, "legacy_app", "other", "myisam_db").unwrap(), UserOutcome::Existing);
    assert!(legacy_app.query("SELECT 1").is_ok(), "an existing account keeps its password");

    // --- collations: what the source databases use vs what the target offers
    let used = collations_used(&root, &["inno_db"]).unwrap();
    assert!(used.contains("utf8mb4_unicode_ci"));
    let avail = collations_available(&root).unwrap();
    assert!(missing_collations(&used, &avail).is_empty());
    let mysql8 = ["utf8mb4_0900_ai_ci".to_string()].into_iter().collect();
    assert_eq!(missing_collations(&mysql8, &avail), ["utf8mb4_0900_ai_ci"], "a MySQL 8 collation is caught before any copy");

    // --- dump to a missing staging dir fails cleanly without leaving a .part behind
    let bad = dir.join("no-such-dir");
    assert!(dump_database(&root, "x.example.org", "inno_db", "src1", &bad, now).is_err());
    assert!(std::fs::read_dir(&staging).unwrap().all(|e| !e.unwrap().file_name().to_string_lossy().ends_with(".part")));
    drop(server);
    let _ = std::fs::remove_dir_all(&dir);
}
