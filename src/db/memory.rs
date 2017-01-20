#![allow(dead_code)]
use std::collections::HashMap;

pub struct MemoryDB {
    user_password: Box<HashMap<String, String>>,
}

impl MemoryDB {
    pub fn new() -> MemoryDB {
        MemoryDB {
            user_password: Box::new(HashMap::new()),
        }
    }
}

impl super::DB for MemoryDB {
    fn add_user_auth(&mut self, user: String, password: String) -> Result<(), String> {
        self.user_password.insert(user, password);
        Ok(())
    }

    fn lookup_user_by_3pid(&self, _: &str, _: &str) -> Result<Option<String>, String> {
        Ok(Some("".to_string()))
    }

    fn lookup_user_by_user_id(&self, user_id: &str) -> Result<Option<String>, String> {
        Ok(Some(user_id.to_string()))
    }

    fn lookup_user_password(&self, user: &str, password: &str) -> Result<bool, String> {
        match self.user_password.get(user) {
            Some(stored_password) => Ok(password == stored_password),
            None => Ok(false),
        }
    }

    fn lookup_home_server(&self, _: &str) -> Result<String, String> {
        Ok("".to_string())
    }
}

//
// Unit Tests
//

#[cfg(test)]
mod test {
    use super::MemoryDB;
    use db::DB;

    #[test]
    fn test_add_user_auth() {
        let mut memory_db = MemoryDB::new();
        assert_eq!(Ok(()), memory_db.add_user_auth("foo".to_string(), "bar".to_string()));
        let result = memory_db.lookup_user_password("foo", "bar");
        assert_eq!(Ok(true), result);
        let result = memory_db.lookup_user_password("foo", "baz");
        assert_eq!(Ok(false), result);
    }
}