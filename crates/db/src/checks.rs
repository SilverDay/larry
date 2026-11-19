//! Checks around the copy: collations, and the app's own database user.

use crate::dump::check_db_name;
use crate::Sql;
use std::collections::BTreeSet;

fn in_list(dbs: &[&str]) -> Result<String, String> {
    for d in dbs {
        check_db_name(d)?;
    }
    Ok(dbs.iter().map(|d| format!("'{d}'")).collect::<Vec<_>>().join(","))
}

/// Collations the given databases use (their defaults and every table's), read on the source.
pub fn collations_used(sql: &dyn Sql, dbs: &[&str]) -> Result<BTreeSet<String>, String> {
    if dbs.is_empty() {
        return Ok(BTreeSet::new());
    }
    let l = in_list(dbs)?;
    let out = sql.query(&format!(
        "SELECT TABLE_COLLATION FROM information_schema.TABLES WHERE TABLE_SCHEMA IN ({l}) AND TABLE_COLLATION IS NOT NULL \
         UNION SELECT DEFAULT_COLLATION_NAME FROM information_schema.SCHEMATA WHERE SCHEMA_NAME IN ({l})"
    ))?;
    Ok(out.lines().map(str::trim).filter(|s| !s.is_empty() && *s != "NULL").map(String::from).collect())
}

/// Collations the server supports (`SHOW COLLATION`), read on the target.
pub fn collations_available(sql: &dyn Sql) -> Result<BTreeSet<String>, String> {
    let out = sql.query("SHOW COLLATION")?;
    Ok(out.lines().filter_map(|l| l.split('\t').next()).map(String::from).filter(|s| !s.is_empty()).collect())
}

/// Used but unavailable, e.g. MySQL 8's `utf8mb4_0900_ai_ci` on MariaDB: fail before any copy.
pub fn missing_collations(used: &BTreeSet<String>, available: &BTreeSet<String>) -> Vec<String> {
    used.difference(available).cloned().collect()
}

/// A MySQL string literal. Backslashes and quotes are escaped; the caller also clears
/// NO_BACKSLASH_ESCAPES for the session (see `create_user_sql`).
pub fn sql_literal(s: &str) -> String {
    let mut o = String::from("'");
    for c in s.chars() {
        match c {
            '\\' => o.push_str("\\\\"),
            '\'' => o.push_str("\\'"),
            '\0' => o.push_str("\\0"),
            '\n' => o.push_str("\\n"),
            '\r' => o.push_str("\\r"),
            '\x1a' => o.push_str("\\Z"),
            c => o.push(c),
        }
    }
    o.push('\'');
    o
}

#[derive(Debug, PartialEq, Eq)]
pub enum UserOutcome {
    Created,
    /// The account already existed: its password is left alone, only the grant is (re)applied.
    Existing,
}

fn check_user(user: &str) -> Result<(), String> {
    if re!(r"^[A-Za-z0-9_.-]{1,80}$").is_match(user) {
        Ok(())
    } else {
        Err(format!("'{user}' is not a usable database user name"))
    }
}

/// The app's DB user: `'<user>'@'localhost'` with that password and rights on its own database only.
/// The password is sent on stdin by the `Sql` implementation; it is never logged or returned.
pub fn ensure_app_user(sql: &dyn Sql, user: &str, password: &str, db: &str) -> Result<UserOutcome, String> {
    check_user(user)?;
    check_db_name(db)?;
    if password.is_empty() {
        return Err(format!("refusing to create passwordless account '{user}'@'localhost'"));
    }
    let n = sql.query(&format!("SELECT COUNT(*) FROM mysql.user WHERE User={} AND Host='localhost'", sql_literal(user)))?;
    let existing = n.trim() != "0";
    let mut stmt = String::from("SET SESSION sql_mode = REPLACE(@@sql_mode, 'NO_BACKSLASH_ESCAPES', '');\n");
    if !existing {
        stmt += &format!("CREATE USER {}@'localhost' IDENTIFIED BY {};\n", sql_literal(user), sql_literal(password));
    }
    stmt += &format!("GRANT ALL PRIVILEGES ON `{db}`.* TO {}@'localhost';\n", sql_literal(user));
    sql.query(&stmt).map_err(|e| e.replace(password, "***"))?;
    Ok(if existing { UserOutcome::Existing } else { UserOutcome::Created })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::FakeSql;

    #[test]
    fn mysql8_collation_is_caught_before_any_copy() {
        let used: BTreeSet<String> = ["utf8mb4_general_ci", "utf8mb4_0900_ai_ci"].iter().map(|s| s.to_string()).collect();
        let avail: BTreeSet<String> = ["utf8mb4_general_ci", "utf8mb4_unicode_ci"].iter().map(|s| s.to_string()).collect();
        assert_eq!(missing_collations(&used, &avail), ["utf8mb4_0900_ai_ci"]);
        assert!(missing_collations(&avail, &avail).is_empty());
        assert!(collations_used(&FakeSql::new(true, 0), &["bad;name"]).is_err());
    }

    #[test]
    fn literals_are_escaped() {
        assert_eq!(sql_literal("a'b\\c"), "'a\\'b\\\\c'");
        assert_eq!(sql_literal("x\ny\0"), "'x\\ny\\0'");
    }

    #[test]
    fn app_user_rules() {
        let sql = FakeSql::new(true, 0);
        assert_eq!(ensure_app_user(&sql, "shop", "p'w", "shop_db").unwrap(), UserOutcome::Created);
        let log = sql.log().join("\n");
        assert!(log.contains("CREATE USER 'shop'@'localhost' IDENTIFIED BY 'p\\'w'"));
        assert!(log.contains("GRANT ALL PRIVILEGES ON `shop_db`.* TO 'shop'@'localhost'"));

        let sql = FakeSql::new(true, 0);
        sql.set_user_rows(1);
        assert_eq!(ensure_app_user(&sql, "shop", "pw", "shop_db").unwrap(), UserOutcome::Existing);
        let log = sql.log().join("\n");
        assert!(!log.contains("CREATE USER"), "an existing account keeps its password");
        assert!(log.contains("GRANT ALL PRIVILEGES"));
        assert!(ensure_app_user(&sql, "shop", "", "shop_db").is_err());
        assert!(ensure_app_user(&sql, "sh op", "pw", "shop_db").is_err());
        assert!(ensure_app_user(&sql, "shop", "pw", "mysql").is_err(), "never grants on a system database");
        assert!(ensure_app_user(&sql, "shop", "pw", "a`b").is_err());
    }
}
