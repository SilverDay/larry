//! What the source database server says about each database: tables that are not InnoDB (the dump
//! has to lock them) and DEFINER accounts of views, triggers, routines and events (they must exist
//! on the target). Read-only `information_schema` queries.

use larry_transport::Cmd;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

#[derive(Debug, Default, Clone, PartialEq)]
pub struct DbFacts {
    /// database -> (table, engine)
    pub non_innodb: BTreeMap<String, Vec<(String, String)>>,
    /// database -> `user@host`
    pub definers: BTreeMap<String, BTreeSet<String>>,
}

const ENGINES_SQL: &str = "SELECT TABLE_SCHEMA, TABLE_NAME, ENGINE FROM information_schema.TABLES WHERE TABLE_TYPE='BASE TABLE' AND ENGINE IS NOT NULL AND ENGINE <> 'InnoDB' AND TABLE_SCHEMA NOT IN ('mysql','sys','information_schema','performance_schema')";
const DEFINERS_SQL: &str = "SELECT DISTINCT s, d FROM (SELECT TABLE_SCHEMA s, DEFINER d FROM information_schema.VIEWS UNION SELECT EVENT_OBJECT_SCHEMA, DEFINER FROM information_schema.TRIGGERS UNION SELECT ROUTINE_SCHEMA, DEFINER FROM information_schema.ROUTINES UNION SELECT EVENT_SCHEMA, DEFINER FROM information_schema.EVENTS) x";

/// Tab-separated rows without headers, as `mysql -N -B` prints them.
pub fn parse(engines: &str, definers: &str) -> DbFacts {
    let mut f = DbFacts::default();
    for l in engines.lines() {
        let c: Vec<&str> = l.split('\t').collect();
        if let [db, t, e] = c[..] {
            f.non_innodb.entry(db.into()).or_default().push((t.into(), e.into()));
        }
    }
    for l in definers.lines() {
        if let Some((db, d)) = l.split_once('\t') {
            if !d.is_empty() {
                f.definers.entry(db.into()).or_default().insert(d.into());
            }
        }
    }
    f
}

pub fn collect(defaults_file: &Path) -> Result<DbFacts, String> {
    let q = |sql: &str| -> Result<String, String> {
        Cmd::new("mysql")
            .arg(format!("--defaults-extra-file={}", defaults_file.display()))
            .args(["-N", "-B"])
            .stdin_data(sql.as_bytes().to_vec())
            .run_checked()
            .map(|o| o.stdout)
            .map_err(|e| format!("database facts: {e}"))
    };
    Ok(parse(&q(ENGINES_SQL)?, &q(DEFINERS_SQL)?))
}

/// Definers that exist on every MariaDB/MySQL server and need no action.
pub fn is_builtin_definer(d: &str) -> bool {
    matches!(d, "root@localhost" | "mariadb.sys@localhost" | "mysql.sys@localhost")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_engines_and_definers() {
        let f = parse("shop\tlog\tMyISAM\nshop\tcache\tMEMORY\nbad line\n", "shop\tapp@localhost\nshop\troot@localhost\nother\t\n");
        assert_eq!(f.non_innodb["shop"], vec![("log".into(), "MyISAM".into()), ("cache".into(), "MEMORY".into())]);
        assert_eq!(f.definers["shop"].len(), 2);
        assert!(!f.definers.contains_key("other"));
        assert!(is_builtin_definer("root@localhost") && !is_builtin_definer("app@localhost"));
    }
}
