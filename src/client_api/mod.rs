use rocket;
use rocket::request::Request;
use rocket_contrib::JSON;

mod login;
mod versions;
pub mod error;

#[error(401)]
fn unauthorized(_: &Request) -> JSON<error::Error> {
    JSON(error::Error{
        errcode : "M_UNAUTHORIZED".to_string(),
        error : "Invalid user or password".to_string(),
    })
}

pub fn mount() -> rocket::Rocket {
    let mut rocket = rocket::ignite();
    rocket = rocket.catch(errors![unauthorized]);
    rocket = versions::mount(rocket);
    rocket = login::mount(rocket);
    rocket
}