use std::fmt;
use toml;

pub fn new(_: &toml::Value) -> Box<DB> {
    Box::new(MockDB {})
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

#[derive(Debug)]
pub struct MockDB {}

impl DB for MockDB {
    fn lookup_user_by_3pid(&self, _: &str, _: &str) -> Result<Option<String>, String> {
        return Ok(Some("".to_string()));
    }

    fn lookup_user_by_user_id(&self, user_id: &str) -> Result<Option<String>, String> {
        return Ok(Some(user_id.to_string()));
    }

    fn lookup_user_password(&self, user: &str, password: &str) -> Result<bool, String> {
        return Ok(user == "foo" && password == "bar");
    }

    fn lookup_home_server(&self, _: &str) -> Result<String, String> {
        return Ok("foobar".to_string());
    }
}
