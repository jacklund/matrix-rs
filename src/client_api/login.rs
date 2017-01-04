use rocket;
use rocket_contrib::JSON;
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

fn authenticate_password(user: &String, password: String) -> bool {
    return user.as_str() == "foo" && password.as_str() == "bar";
}

fn password_request(login_request: LoginRequest) -> Result<status::Custom<JSON<LoginResponse>>, Failure> {
    match login_request.user {
        None => return Err(Failure(Status::Unauthorized)),
        Some(user) =>
            match authenticate_password(&user, login_request.password) {
                true =>
                    return Ok(status::Custom(Status::Ok, JSON(LoginResponse{
                              access_token: String::from("abcdef"),
                              home_server: String::from("foobar"),
                              user_id: user,
                              refresh_token: None,
                    }))),
                false => return Err(Failure(Status::Unauthorized)),
            }
    }
}

#[post("/login", format="application/json", data="<json_request>")]
fn login<'r>(json_request: JSON<LoginRequest>) -> Result<status::Custom<JSON<LoginResponse>>, Failure> {
    let login_request: LoginRequest = json_request.0;
    match login_request.login_type.as_str() {
        "m.login.password" => return password_request(login_request),
        _ => return Err(Failure(Status::BadRequest)),
    }
}

pub fn mount(rocket: rocket::Rocket) -> rocket::Rocket {
    return rocket.mount("/_matrix/client/r0", routes![login]);
}