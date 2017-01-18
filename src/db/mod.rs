use std::fmt;
use toml;

pub mod mock_db;

pub fn new(_: &toml::Value) -> Box<DB> {
    Box::new(mock_db::MockDB {})
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