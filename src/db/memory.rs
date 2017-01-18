#![allow(dead_code)]
use std::collections::HashMap;

pub struct MemoryDB {
    db: Box<HashMap<String, String>>,
}

impl MemoryDB {
    pub fn new() -> MemoryDB {
        MemoryDB {
            db: Box::new(HashMap::new()),
        }
    }

    pub fn add_value<V>(&mut self, key: String, value: V) -> () where V: ToString {
        self.db.insert(key, value.to_string());
    }
}

impl super::DB for MemoryDB {
    fn lookup_user_by_3pid(&self, medium: &str, address: &str) -> Result<Option<String>, String> {
        Ok(Some("".to_string()))
    }

    fn lookup_user_by_user_id(&self, user_id: &str) -> Result<Option<String>, String> {
        Ok(Some("".to_string()))
    }

    fn lookup_user_password(&self, user: &str, password: &str) -> Result<bool, String> {
        Ok(true)
    }

    fn lookup_home_server(&self, user: &str) -> Result<String, String> {
        Ok("".to_string())
    }
}