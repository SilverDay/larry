//! Test helpers: gzip fixtures and a fake database server that records every call.

use crate::{DumpMode, Sql};
use flate2::{write::GzEncoder, Compression};
use std::cell::{Cell, RefCell};
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

pub fn tmp(n: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("larry-db-{n}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

pub fn gz(dir: &Path, name: &str, text: &str) -> PathBuf {
    let p = dir.join(name);
    let mut e = GzEncoder::new(File::create(&p).unwrap(), Compression::fast());
    e.write_all(text.as_bytes()).unwrap();
    e.finish().unwrap();
    p
}

pub struct FakeSql {
    log: RefCell<Vec<String>>,
    exists: Cell<bool>,
    tables: Cell<u64>,
    nontx: Cell<u64>,
    user_rows: Cell<u64>,
    pub fail_dump: bool,
    /// Tables the fake "creates" when a dump is loaded.
    pub loads_tables: u64,
}

impl FakeSql {
    pub fn new(exists: bool, tables: u64) -> Self {
        FakeSql { log: RefCell::new(vec![]), exists: Cell::new(exists), tables: Cell::new(tables), nontx: Cell::new(0), user_rows: Cell::new(0), fail_dump: false, loads_tables: 2 }
    }
    pub fn log(&self) -> Vec<String> {
        self.log.borrow().clone()
    }
    pub fn set_nontx(&self, n: u64) {
        self.nontx.set(n)
    }
    pub fn set_user_rows(&self, n: u64) {
        self.user_rows.set(n)
    }
}

impl Sql for FakeSql {
    fn query(&self, sql: &str) -> Result<String, String> {
        self.log.borrow_mut().push(format!("query {sql}"));
        if sql.starts_with("DROP DATABASE") {
            self.exists.set(false);
            self.tables.set(0);
            return Ok(String::new());
        }
        Ok(if sql.contains("SCHEMATA") {
            (self.exists.get() as u8).to_string()
        } else if sql.contains("ENGINE NOT IN") {
            self.nontx.get().to_string()
        } else if sql.contains("information_schema.TABLES") {
            self.tables.get().to_string()
        } else if sql.contains("mysql.user") {
            self.user_rows.get().to_string()
        } else {
            String::new()
        })
    }

    fn dump(&self, db: &str, mode: DumpMode, out: &mut (dyn Write + Send)) -> Result<(), String> {
        self.log.borrow_mut().push(format!("dump {db} {}", mode.flag()));
        if self.fail_dump {
            let _ = out.write_all(b"partial");
            return Err("mysqldump: boom".into());
        }
        out.write_all(b"-- fake dump\n").map_err(|e| e.to_string())
    }

    fn load(&self, input: &mut (dyn Read + Send)) -> Result<(), String> {
        let mut s = String::new();
        input.read_to_string(&mut s).map_err(|e| e.to_string())?;
        self.log.borrow_mut().push(format!("load {} bytes", s.len()));
        self.exists.set(true);
        self.tables.set(self.loads_tables);
        Ok(())
    }
}
