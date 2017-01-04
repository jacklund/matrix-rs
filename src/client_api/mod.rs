use rocket;

mod login;
mod versions;
pub mod error;

pub fn mount() -> rocket::Rocket {
    let mut rocket = rocket::ignite();
    rocket = versions::mount(rocket);
    rocket = login::mount(rocket);
    rocket
}