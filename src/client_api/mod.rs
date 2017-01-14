use rocket;
use serde_json;

mod login;
mod versions;
mod error;

// 404 Handler
#[error(404)]
fn not_found() -> String {
    serde_json::to_string(&error::Error {
        errcode: error::Errcode::NotFound,
        error: "Not Found".to_string(),
    }).unwrap()
}

// 400 Handler
#[error(400)]
fn bad_request() -> String {
    serde_json::to_string(&error::Error {
        errcode: error::Errcode::BadJson,
        error: "Bad JSON".to_string(),
    }).unwrap()
}

// Mount all the submodules' routes
pub fn mount() -> rocket::Rocket {
    let mut rocket = rocket::ignite();
    rocket = rocket.catch(errors![bad_request, not_found]);
    rocket = versions::mount(rocket);
    rocket = login::mount(rocket);
    rocket
}