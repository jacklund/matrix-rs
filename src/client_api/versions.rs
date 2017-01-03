use rocket;
use rocket_contrib::JSON;
use std::collections::HashMap;

type Versions = HashMap<&'static str, [&'static str; 1]>;

#[get("/versions")]
fn versions() -> JSON<Versions> {
    JSON(map!{
        "versions" => ["r0.2.0"]
    })
}

pub fn mount(rocket: rocket::Rocket) -> rocket::Rocket {
    return rocket.mount("/_matrix/client", routes![versions]);
}