use rocket;
use rocket_contrib::JSON;
use rocket::data::FromData;
use rocket::http::Status;
use rocket::response::status;
use rocket::response::Failure;

#[derive(Deserialize, Debug)]
struct LoginRequest {
    password: String,
    medium: Option<String>,
    #[serde(rename="type")]
    login_type: String,
    user: Option<String>,
    address: Option<String>,
}

#[derive(Serialize, Debug)]
struct LoginResponse {
    access_token: String,
    home_server: String,
    user_id: String,
    refresh_token: Option<String>,
}

#[post("/login", format="application/json", data="<login_request>")]
fn login<'r>(login_request: JSON<LoginRequest>) -> Result<status::Custom<JSON<LoginResponse>>, Failure> {
    if login_request.0.login_type != "m.login.password" {
        return Err(Failure(Status::BadRequest));
    }
    let authenticated;
    match login_request.0.user.as_ref().map(String::as_ref) {
        Some("foo") if login_request.0.password == "bar" => authenticated = true,
        _ => authenticated = false,
    }
    if !authenticated {
        return Err(Failure(Status::Unauthorized));
    }
    Ok(status::Custom(Status::Ok, JSON(LoginResponse{
        access_token: String::from("abcdef"),
        home_server: String::from("foobar"),
        user_id: login_request.0.user.unwrap(),
        refresh_token: None,
    })))
}

pub fn mount(rocket: rocket::Rocket) -> rocket::Rocket {
    return rocket.mount("/_matrix/client/r0", routes![login]);
}