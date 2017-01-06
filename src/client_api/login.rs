use rocket;
use rocket_contrib::JSON;
use rocket::http::Status;
use rocket::response::status;
use serde_json;
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

fn authenticate_password(user: &str, password: &str) -> Result<bool, String> {
    return Ok(user == "foo" && password == "bar");
}

fn lookup_3pid(_ : String, _ : String) -> Result<Option<String>, String> {
    return Ok(Some("".to_string()));
}

fn get_user_id(login_request: LoginRequest) -> Result<Option<String>, String> {
    if login_request.medium.is_some() && login_request.address.is_some() {
        return lookup_3pid(login_request.medium.unwrap().clone(), login_request.address.unwrap().clone());
    } else if login_request.user.is_some() {
        return Ok(Some(login_request.user.unwrap().clone()));
    } else {
        return Ok(None);
    }
}

fn get_login_response(_ : &str) -> Result<Option<LoginResponse>, String> {
    return Ok(Some(LoginResponse {
        access_token: String::from("abcdef"),
        home_server: String::from("foobar"),
        user_id: String::from("Foo Bar"),
        refresh_token: None,
    }));
}

fn handle_password_request(login_request: LoginRequest) -> Result<Option<LoginResponse>, String> {
    let password = login_request.password.clone();
    match get_user_id(login_request) {
        Ok(user_id) => match user_id {
            Some(user_id) => match authenticate_password(user_id.as_str(), password.as_str()) {
                Ok(authenticated) => match authenticated {
                    true  => return get_login_response(user_id.as_str()),
                    false => return Ok(None),
                },
                Err(error_string) => return Err(error_string),
            },
            None => return Ok(None),
        },
        Err(error_string) => return Err(error_string),
    };
}

#[get("/login")]
fn get_flows() -> JSON<serde_json::Value> {
    let mut flow = serde_json::Map::new();
    flow.insert("type".to_string(), serde_json::Value::String("m.login.password".to_string()));
    let mut value = serde_json::Map::new();
    value.insert("flows".to_string(), serde_json::Value::Array(vec![serde_json::Value::Object(flow)]));
    return JSON(serde_json::Value::Object(value));
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

    match authenticated {
        Ok(login_response) => match login_response {
            Some(login_response) => return Ok(status::Custom(Status::Ok, JSON(login_response))),
            None                 => return Err(status::Custom(Status::Forbidden, JSON(error::Error {
                errcode : error::errcodes::FORBIDDEN.to_string(),
                error : "Bad login".to_string(),
            }))),
        },
        Err(error_string)  => return Err(status::Custom(Status::InternalServerError,
            JSON(error::Error {
                errcode : error::errcodes::UNKNOWN.to_string(),
                error   : error_string,
        }))),
    }
}

pub fn mount(rocket: rocket::Rocket) -> rocket::Rocket {
    return rocket.mount("/_matrix/client/r0", routes![get_flows, login]);
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

    #[test]
    fn test_get_flows() {
        let rocket = rocket::ignite().mount("/_matrix/client/r0", routes![super::get_flows]);
        let mut req = MockRequest::new(Method::Get, "/_matrix/client/r0/login");
        let mut response = req.dispatch_with(&rocket);

        assert_eq!(response.status(), Status::Ok);

        let body_str = response.body().and_then(|b| b.into_string());
        let json_response: serde_json::Value = serde_json::from_str(body_str.unwrap().as_str()).unwrap();
        let flows = json_response.as_object().unwrap().get("flows").unwrap().as_array().unwrap();
        assert_eq!(1, flows.len());
        let flow = flows[0].as_object().unwrap();
        assert_eq!("m.login.password", flow.get("type").unwrap().as_str().unwrap());
    }

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
    fn test_password_login_authenticated() {
        let rocket = rocket::ignite().mount("/_matrix/client/r0", routes![super::login]);
        let mut req = login_with_password_request("foo", "bar", "m.login.password");
        let mut response = req.dispatch_with(&rocket);

        assert_eq!(response.status(), Status::Ok);

        let body_str = response.body().and_then(|b| b.into_string());
        let login_response : LoginResponse = serde_json::from_str(body_str.unwrap().as_str()).unwrap();
        assert!(!login_response.access_token.is_empty());
        assert!(!login_response.home_server.is_empty());
        assert!(!login_response.user_id.is_empty());
    }

    #[test]
    fn test_password_login_failed_authentication() {
        let rocket = rocket::ignite().mount("/_matrix/client/r0", routes![super::login]);
        let mut req = login_with_password_request("foo", "baz", "m.login.password");
        let mut response = req.dispatch_with(&rocket);

        assert_eq!(response.status(), Status::Forbidden);

        let body_str = response.body().and_then(|b| b.into_string());
        let error : error::Error = serde_json::from_str(body_str.unwrap().as_str()).unwrap();
        assert_eq!(error.errcode, error::errcodes::FORBIDDEN);
    }

    #[test]
    fn test_password_login_bad_login_type() {
        let rocket = rocket::ignite().mount("/_matrix/client/r0", routes![super::login]);
        let mut req = login_with_password_request("foo", "baz", "");
        let mut response = req.dispatch_with(&rocket);

        assert_eq!(response.status(), Status::BadRequest);

        let body_str = response.body().and_then(|b| b.into_string());
        let error : super::error::Error = serde_json::from_str(body_str.unwrap().as_str()).unwrap();
        assert_eq!(error.errcode, error::errcodes::UNKNOWN);
    }
}