pub trait DB {
    fn lookup_user_by_3pid(&self, medium: &str, address: &str) -> Result<Option<String>, String>;
    fn lookup_user_by_user_id(&self, user_id: &str) -> Result<Option<String>, String>;
    fn lookup_user_password(&self, user: &str, password: &str) -> Result<bool, String>;
}

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
}
