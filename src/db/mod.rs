use std::fmt;
use toml;

pub mod mock_db;
pub mod memory;

pub trait DB
    where Self: Sync
{
    fn add_user_auth(&mut self, user: String, password: String) -> Result<(), String>;
    fn lookup_user_by_3pid(&self, medium: &str, address: &str) -> Result<Option<String>, String>;
    fn lookup_user_by_user_id(&self, user_id: &str) -> Result<Option<String>, String>;
    fn lookup_user_password(&self, user: String, password: String) -> Result<bool, String>;
    fn lookup_home_server(&self, user: &str) -> Result<Option<String>, String>;
}

static mut DB_INSTANCE: Option<Box<DB>> = None;

// Initialize the DB using configuration values
pub fn initialize(config: &toml::Value) {
    match config.lookup("type") {
        Some(value) => {
            println!("DB type is {}", value);
            match value.as_str() {
                Some("mock") => unsafe { DB_INSTANCE = Some(Box::new(mock_db::MockDB {})) },
                Some("memory") => unsafe { DB_INSTANCE = Some(Box::new(memory::MemoryDB::new())) },
                _ => panic!("Unknown DB type {:?}", value.as_str()),
            }
        }
        None => panic!("No DB type configured"),
    }
}

// Get a reference to the DB impl
pub fn get() -> &'static mut DB {
    unsafe {
        // Needs some 'splainin.
        // Don't want to return Option<Box<DB>>, because it will always try to move it when I unwrap.
        // Instead, we return a &mut DB, which we create by calling as_mut() on the option to get
        // an &mut Box<DB>, and then call map(|b| b.as_mut()) to convert that to an &mut DB, and then
        // we unwrap that to return the reference
        DB_INSTANCE.as_mut().map(|b| b.as_mut()).unwrap()
    }
}

impl fmt::Debug for DB {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "DB")
    }
}