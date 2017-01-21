use db::DB;

#[derive(Debug)]
pub struct MockDB {}

impl DB for MockDB {
    fn add_user_auth(&mut self, _: String, _: String) -> Result<(), String> {
        Ok(())
    }

    fn lookup_user_by_3pid(&self, _: &str, _: &str) -> Result<Option<String>, String> {
        Ok(Some("".to_string()))
    }

    fn lookup_user_by_user_id(&self, user_id: &str) -> Result<Option<String>, String> {
        Ok(Some(user_id.to_string()))
    }

    fn lookup_user_password(&self, user: String, password: String) -> Result<bool, String> {
        Ok(user == "foo" && password == "bar")
    }

    fn lookup_home_server(&self, _: &str) -> Result<Option<String>, String> {
        Ok(Some("foobar".to_string()))
    }
}