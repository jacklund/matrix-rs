use rocket;
use rocket_contrib::JSON;
use rocket::http::Status;
use rocket::response::status;
use super::error;

#[derive(Serialize, Deserialize, Debug)]
struct LoginRequest {
    password: String,
    medium: Option<String>,
    #[serde(rename="type")]
    login_type: String,
    user: Option<String>,
    address: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
struct LoginResponse {
    access_token: String,
    home_server: String,
    user_id: String,
    refresh_token: Option<String>,
}

fn authenticate_password(user: &String, password: &String) -> bool {
    return user.as_str() == "foo" && password.as_str() == "bar";
}

fn lookup_3pid(_ : String, _ : String) -> String {
    return "".to_string();
}

fn handle_password_request(login_request: LoginRequest) -> bool {
    let user_id: String;
    if login_request.medium.is_some() && login_request.address.is_some() {
        user_id = lookup_3pid(login_request.medium.unwrap(), login_request.address.unwrap());
    } else {
        if login_request.user.is_some() {
            user_id = login_request.user.unwrap();
        } else {
            return false;
        }
    }

    return authenticate_password(&user_id, &login_request.password);
}

#[post("/login", format="application/json", data="<json_request>")]
fn login(json_request: JSON<LoginRequest>) -> Result<status::Custom<JSON<LoginResponse>>, status::Custom<JSON<error::Error>>> {
    let login_request: LoginRequest = json_request.0;

    let authenticated;
    match login_request.login_type.as_str() {
        "m.login.password" => authenticated = handle_password_request(login_request),
        _ => return Err(status::Custom(Status::BadRequest, JSON(error::Error{
            errcode : error::errcodes::UNKNOWN.to_string(),
            error : "Bad login type".to_string(),
        }))),
    }

    if authenticated {
        return Ok(status::Custom(Status::Ok, JSON(LoginResponse {
            access_token: String::from("abcdef"),
            home_server: String::from("foobar"),
            user_id: String::from("Foo Bar"),
            refresh_token: None,
        })));
    } else {
        return Err(status::Custom(Status::Forbidden, JSON(error::Error {
            errcode : error::errcodes::FORBIDDEN.to_string(),
            error : "Bad login".to_string(),
        })))
    }
}

pub fn mount(rocket: rocket::Rocket) -> rocket::Rocket {
    return rocket.mount("/_matrix/client/r0", routes![login]);
}

#[cfg(test)]
mod test {
    use super::error;
    use super::rocket;
    use super::{LoginRequest, LoginResponse};
    use rocket::http::{Status, Method};
    use rocket::http::ContentType;
    use rocket::testing::MockRequest;
    use serde_json;

    fn login_with_password_request(user: &str, password: &str, login_type: &str) -> MockRequest {
        let login_request = LoginRequest {
            password : password.to_string(),
            login_type: login_type.to_string(),
            user: Some(user.to_string()),
            address: None,
            medium: None,
        };
        MockRequest::new(Method::Post, "/_matrix/client/r0/login")
            .header(ContentType::JSON)
            .body(serde_json::to_string(&login_request).unwrap())
    }

    #[test]
    fn test_password_login() {
        let rocket = rocket::ignite().mount("/_matrix/client/r0", routes![super::login]);
        let mut req = login_with_password_request("foo", "bar", "m.login.password");
        let mut response = req.dispatch_with(&rocket);

        assert_eq!(response.status(), Status::Ok);

        let body_str = response.body().and_then(|b| b.into_string());
        let login_response : LoginResponse = serde_json::from_str(body_str.unwrap().as_str()).unwrap();
        assert!(!login_response.access_token.is_empty());
        assert!(!login_response.home_server.is_empty());
        assert!(!login_response.user_id.is_empty());

        let mut req = login_with_password_request("foo", "baz", "m.login.password");
        let mut response = req.dispatch_with(&rocket);
        assert_eq!(response.status(), Status::Forbidden);
        let body_str = response.body().and_then(|b| b.into_string());
        let error : error::Error = serde_json::from_str(body_str.unwrap().as_str()).unwrap();
        assert_eq!(error.errcode, error::errcodes::FORBIDDEN);

        let mut req = login_with_password_request("foo", "baz", "");
        let mut response = req.dispatch_with(&rocket);
        assert_eq!(response.status(), Status::BadRequest);
        let body_str = response.body().and_then(|b| b.into_string());
        let error : super::error::Error = serde_json::from_str(body_str.unwrap().as_str()).unwrap();
        assert_eq!(error.errcode, error::errcodes::UNKNOWN);
    }
}