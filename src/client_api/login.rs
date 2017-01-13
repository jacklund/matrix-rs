use rocket;
use rocket_contrib::JSON;
use rocket::http::Status;
use rocket::response::status;
use serde_json;
use std::collections::HashMap;
use super::error;

#[derive(Serialize, Deserialize, Debug)]
struct LoginResponse {
    access_token: String,
    home_server: String,
    user_id: String,
    refresh_token: Option<String>,
}

type AuthFn = fn(&str, &serde_json::Value) -> Result<bool, error::Errcode>;

lazy_static! {
    static ref AUTHENTICATION_METHODS: HashMap<&'static str, AuthFn> = {
        let mut m: HashMap<&'static str, AuthFn> = HashMap::new();
        m.insert("m.login.password", authenticate_password);
        m
    };
}

fn authenticate_password(user: &str, login_request: &serde_json::Value) -> Result<bool, error::Errcode> {
    let password_opt = get_login_request_value(&login_request, "password");
    match password_opt {
        Some(password) => return Ok(user == "foo" && password == "bar"),
        None           => return Err(error::Errcode::MissingParam),
    }
}

fn lookup_3pid(_ : &str, _ : &str) -> Result<Option<String>, error::Errcode> {
    return Ok(Some("".to_string()));
}

fn get_login_request_value<'r>(login_request: &'r serde_json::Value, key: &str) -> Option<&'r str> {
    match login_request.find(key) {
        Some(value) => value.as_str(),
        None        => None,
    }
}

fn get_user_id(login_request: &serde_json::Value) -> Result<Option<String>, error::Errcode> {
    match get_login_request_value(login_request, "medium") {
        Some(medium) => match get_login_request_value(login_request, "address") {
            Some(address) => lookup_3pid(medium, address),
            None          => Ok(None),
        },
        None         => match get_login_request_value(login_request, "user") {
            Some(user) => Ok(Some(user.to_string())),
            None       => Ok(None),
        }
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
    match try!(get_user_id(&login_request)) {
        Some(user_id) => {
            match try!(auth_fn(user_id.as_str(), login_request)) {
                true  => return get_login_response(user_id.as_str()),
                false => return Ok(None),
            }
        },
        None          => Ok(None)
    }
}

fn get_login_type(login_request: &serde_json::Value) -> Option<&str> {
    return get_login_request_value(&login_request, "type");
}

fn create_error(status: Status, errcode: error::Errcode, error: &'static str) -> status::Custom<JSON<error::Error>> {
    status::Custom(status, JSON(error::Error {
        errcode: errcode,
        error: error.to_string(),
    }))
}

fn authenticate(login_request: JSON<serde_json::Value>) -> Result<Option<LoginResponse>, status::Custom<JSON<error::Error>>> {
    match get_login_type(&login_request) {
        Some(login_type) => {
            match AUTHENTICATION_METHODS.get(login_type) {
                Some(authentication_method) => match handle_authentication_request(*authentication_method, &login_request) {
                    Ok(response) => return Ok(response),
                    Err(errcode) => return Err(create_error(Status::InternalServerError, errcode, "Internal error")),
                    },
                None => return Err(create_error(Status::BadRequest, error::Errcode::Unknown, "Unknown login type")),
            }
        }
        None => return Err(create_error(Status::BadRequest, error::Errcode::BadJson, "No authentication type found")),
    }
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
    match try!(authenticate(login_request)) {
        Some(login_response) => return Ok(status::Custom(Status::Ok, JSON(login_response))),
        None                 => return Err(status::Custom(Status::Forbidden, JSON(error::Error {
            errcode : error::Errcode::Forbidden,
            error : "Bad login".to_string(),
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
        // println!("{:?}", serde_json::from_str::<error::Error>(body_str.unwrap().as_str()));
        let error : error::Error = serde_json::from_str(body_str.unwrap().as_str()).unwrap();
        assert_eq!(error.errcode, error::Errcode::Forbidden);
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