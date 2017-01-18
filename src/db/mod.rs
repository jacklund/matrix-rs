use std::fmt;
use toml;

pub mod mock_db;
pub mod memory;

pub fn new(config: &toml::Value) -> Box<DB> {
    match config.lookup("type") {
        Some(value) => match value.as_str() {
            Some("mock") => Box::new(mock_db::MockDB {}),
            Some("memory") => Box::new(memory::MemoryDB::new()),
            _ => panic!("Unknown DB type {:?}", value.as_str()),
        },
        None => panic!("No DB type configured"),
    }
}

pub trait DB where Self: Sync {
    fn lookup_user_by_3pid(&self, medium: &str, address: &str) -> Result<Option<String>, String>;
    fn lookup_user_by_user_id(&self, user_id: &str) -> Result<Option<String>, String>;
    fn lookup_user_password(&self, user: &str, password: &str) -> Result<bool, String>;
    fn lookup_home_server(&self, user: &str) -> Result<String, String>;
}

impl fmt::Debug for DB {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "DB")
    }
}