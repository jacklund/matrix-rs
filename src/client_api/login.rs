use rocket;
use rocket_contrib::JSON;
use rocket::http::Status;
use rocket::response::status;
use serde_json;
use super::error;

#[derive(Serialize, Deserialize, Debug)]
struct LoginResponse {
    access_token: String,
    home_server: String,
    user_id: String,
    refresh_token: Option<String>,
}

fn authenticate_password(user: &str, login_request: &serde_json::Value) -> Result<bool, error::Errcode> {
    let password_opt = get_login_request_value(&login_request, "password");
    if password_opt.is_none() {
        return Err(error::Errcode::MissingParam);
    }
    let password =  password_opt.unwrap();
    return Ok(user == "foo" && password == "bar");
}

fn lookup_3pid(_ : &str, _ : &str) -> Result<Option<String>, error::Errcode> {
    return Ok(Some("".to_string()));
}

fn get_login_request_value<'r>(login_request: &'r serde_json::Value, key: &str) -> Option<&'r str> {
    let opt = login_request.find(key);
    if opt.is_none() {
        return None;
    }
    return opt.unwrap().as_str();
}

fn get_user_id(login_request: &serde_json::Value) -> Result<Option<String>, error::Errcode> {
    let medium = get_login_request_value(login_request, "medium");
    let address = get_login_request_value(login_request, "address");
    let user = get_login_request_value(login_request, "user");
    if medium.is_some() && address.is_some() {
        return lookup_3pid(medium.unwrap(), address.unwrap());
    } else if user.is_some() {
        return Ok(Some(user.unwrap().to_string()));
    } else {
        return Ok(None);
    }
}

fn get_login_response(_ : &str) -> Result<Option<LoginResponse>, error::Errcode> {
    return Ok(Some(LoginResponse {
        access_token: String::from("abcdef"),
        home_server: String::from("foobar"),
        user_id: String::from("Foo Bar"),
        refresh_token: None,
    }));
}

fn handle_authentication_request(auth_fn: fn(&str, &serde_json::Value) -> Result<bool, error::Errcode>, login_request: &serde_json::Value) -> Result<Option<LoginResponse>, error::Errcode> {
    let user_id = try!(get_user_id(&login_request));
    user_id.map_or_else(
        || return Ok(None),
        |user_id| {
            let authenticated = try!(auth_fn(user_id.as_str(), login_request));
            match authenticated {
                true  => return get_login_response(user_id.as_str()),
                false => return Ok(None),
            }
        })
}

fn get_login_type(login_request: &serde_json::Value) -> Option<&str> {
    return get_login_request_value(&login_request, "type");
}

#[get("/login")]
fn get_flows() -> JSON<serde_json::Value> {
    let mut flow = serde_json::Map::new();
    flow.insert("type".to_string(), serde_json::Value::String("m.login.password".to_string()));
    let mut value = serde_json::Map::new();
    value.insert("flows".to_string(), serde_json::Value::Array(vec![serde_json::Value::Object(flow)]));
    return JSON(serde_json::Value::Object(value));
}

#[post("/login", format="application/json", data="<login_request>")]
fn login(login_request: JSON<serde_json::Value>) -> Result<status::Custom<JSON<LoginResponse>>, status::Custom<JSON<error::Error>>> {
    let authenticated;
    match get_login_type(&login_request) {
        Some(login_type) => {
            match login_type {
                "m.login.password" => authenticated = handle_authentication_request(authenticate_password, &login_request),
                _ => return Err(status::Custom(Status::BadRequest, JSON(error::Error{
                    errcode : error::Errcode::Unknown,
                    error : "Bad login type".to_string(),
                }))),
            }
        }
        None => return Err(status::Custom(Status::BadRequest, JSON(error::Error{
            errcode : error::Errcode::BadJson,
            error : "No authentication type found".to_string(),
        }))),
    }

    match authenticated {
        Ok(login_response) => match login_response {
            Some(login_response) => return Ok(status::Custom(Status::Ok, JSON(login_response))),
            None                 => return Err(status::Custom(Status::Forbidden, JSON(error::Error {
                errcode : error::Errcode::Forbidden,
                error : "Bad login".to_string(),
            }))),
        },
        Err(errcode)  => return Err(status::Custom(Status::InternalServerError,
            JSON(error::Error {
                errcode : errcode,
                error   : "Internal error".to_string(),
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
    use super::LoginResponse;
    use rocket::http::{Status, Method};
    use rocket::http::ContentType;
    use rocket::testing::MockRequest;
    use serde_json;

    #[derive(Serialize, Debug)]
    struct LoginRequest<'r> {
        password: String,
        medium: Option<String>,
        #[serde(rename="type")]
        login_type: String,
        user: Option<&'r str>,
        address: Option<String>,
    }

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

    fn login_with_password_request(user: Option<&str>, password: &str, login_type: &str) -> MockRequest {
        let login_request = LoginRequest {
            password : password.to_string(),
            login_type: login_type.to_string(),
            user: user,
            address: None,
            medium: None,
        };
        MockRequest::new(Method::Post, "/_matrix/client/r0/login")
            .header(ContentType::JSON)
            .body(serde_json::to_string(&login_request).unwrap())
    }

    #[test]
    fn test_authenticate_bad_json() {
        let rocket = super::super::mount();
        let mut req = MockRequest::new(Method::Post, "/_matrix/client/r0/login")
            .header(ContentType::JSON)
            .body("!2qwjoldskfi33903");
        let mut response = req.dispatch_with(&rocket);

        assert_eq!(response.status(), Status::BadRequest);

        let body_str = response.body().and_then(|b| b.into_string());
        assert_eq!(Some("{\"errcode\":\"M_BAD_JSON\",\"error\":\"Bad JSON\"}".to_string()), body_str);
    }

    #[test]
    fn test_authenticate_not_found() {
        let rocket = super::super::mount();
        let login_request = LoginRequest {
            password : "bar".to_string(),
            login_type: "m.login.password".to_string(),
            user: Some("foo"),
            address: None,
            medium: None,
        };
        let mut req = MockRequest::new(Method::Post, "/_matrix/client/r0/foobar")
            .header(ContentType::JSON)
            .body(serde_json::to_string(&login_request).unwrap());
        let mut response = req.dispatch_with(&rocket);

        assert_eq!(response.status(), Status::NotFound);

        let body_str = response.body().and_then(|b| b.into_string());
        assert_eq!(Some("{\"errcode\":\"M_NOT_FOUND\",\"error\":\"Not Found\"}".to_string()), body_str);
    }

    #[test]
    fn test_password_login_authenticated() {
        let rocket = super::super::mount();
        let mut req = login_with_password_request(Some("foo"), "bar", "m.login.password");
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
        let rocket = super::super::mount();
        let mut req = login_with_password_request(Some("foo"), "baz", "m.login.password");
        let mut response = req.dispatch_with(&rocket);

        assert_eq!(response.status(), Status::Forbidden);

        let body_str = response.body().and_then(|b| b.into_string());
        println!("{:?}", serde_json::from_str::<error::Error>(body_str.unwrap().as_str()));
        // let error : error::Error = serde_json::from_str(body_str.unwrap().as_str()).unwrap();
        // assert_eq!(error.errcode, error::Errcode::Forbidden);
    }

    #[test]
    fn test_password_login_bad_login_type() {
        let rocket = super::super::mount();
        let mut req = login_with_password_request(Some("foo"), "baz", "");
        let mut response = req.dispatch_with(&rocket);

        assert_eq!(response.status(), Status::BadRequest);

        let body_str = response.body().and_then(|b| b.into_string());
        let error : super::error::Error = serde_json::from_str(body_str.unwrap().as_str()).unwrap();
        assert_eq!(error.errcode, error::Errcode::Unknown);
    }

    #[test]
    fn test_password_login_no_user_id() {
        let rocket = super::super::mount();
        let mut req = login_with_password_request(None, "baz", "m.login.password");
        let mut response = req.dispatch_with(&rocket);

        assert_eq!(response.status(), Status::Forbidden);

        let body_str = response.body().and_then(|b| b.into_string());
        println!("{:?}", body_str);
        let error : serde_json::Map<String, String> = serde_json::from_str(body_str.unwrap().as_str()).unwrap();
        assert_eq!("M_FORBIDDEN", error.get("errcode").unwrap().as_str());
    }
}