use rocket;
use rocket_contrib::JSON;
use rocket::http::Status;
use rocket::response::status;
use serde_json;
use std::collections::HashMap;
use std::fmt;
use std::convert::From;
use super::error;
use super::super::db;

// Login response struct
#[derive(Serialize, Deserialize, Debug)]
struct LoginResponse {
    access_token: String,
    home_server: String,
    user_id: String,
    refresh_token: Option<String>,
}

// enum Error {
//     Errstring(String),
//     Errcode(error::Errcode),
// }

pub enum AuthError {
    MissingValue(&'static str),
    SystemError(String),
    UnknownAuthMethod(String),
}

impl From<AuthError> for status::Custom<JSON<error::Error>> {
    fn from(error: AuthError) -> status::Custom<JSON<error::Error>> {
        match error {
            AuthError::MissingValue(missing_value) => {
                status::Custom(Status::BadRequest,
                               JSON(error::Error {
                                   errcode: error::Errcode::BadJson,
                                   error: fmt::format(format_args!("Missing value {}",
                                                                   missing_value)),
                               }))
            }
            AuthError::SystemError(_) => {
                status::Custom(Status::InternalServerError,
                               JSON(error::Error {
                                   errcode: error::Errcode::Unknown,
                                   error: "Server Error".to_string(),
                               }))
            }
            AuthError::UnknownAuthMethod(_) => {
                status::Custom(Status::BadRequest,
                               JSON(error::Error {
                                   errcode: error::Errcode::BadJson,
                                   error: "Server Error".to_string(),
                               }))
            }
        }
    }
}

macro_rules! get_error {
    ( $( $x:expr ), + ) => {
        $( match $x {
            Ok(value) => Ok(value),
            Err(errstring) => Err(AuthError::SystemError(errstring)),
        } )+
    }
}

// Prototype of the authentication function
type AuthFn = fn(&serde_json::Value) -> Result<bool, AuthError>;

// Map from login types to authentication functions
lazy_static! {
    static ref AUTHENTICATION_METHODS: HashMap<&'static str, AuthFn> = {
        let mut m: HashMap<&'static str, AuthFn> = HashMap::new();
        m.insert("m.login.password", authenticate_password);
        m
    };
}

// Password authentication function
fn authenticate_password(login_request: &serde_json::Value) -> Result<bool, AuthError> {
    let user_opt = try!(get_user_id(&login_request));
    match user_opt {
        Some(user) => {
            let password_opt = get_login_request_value(&login_request, "password");
            match password_opt {
                Some(password) => {
                    get_error!(db::get().lookup_user_password(user, password.to_string()))
                }
                None => return Err(AuthError::MissingValue("password")),
            }
        }
        None => Err(AuthError::MissingValue("user")),
    }
}

// Lookup user by 3pid
fn lookup_3pid(medium: &str, address: &str) -> Result<Option<String>, AuthError> {
    return get_error!(db::get().lookup_user_by_3pid(medium, address));
}

// Get a value from the login request
fn get_login_request_value<'r>(login_request: &'r serde_json::Value, key: &str) -> Option<&'r str> {
    match login_request.find(key) {
        Some(value) => {
            match value.as_str() {
                Some(string) => Some(string),
                None => None,
            }
        }
        None => None,
    }
}

// Get the user ID, either by 3pid or from the login request
fn get_user_id(login_request: &serde_json::Value) -> Result<Option<String>, AuthError> {
    match get_login_request_value(login_request, "medium") {
        Some(medium) => {
            match get_login_request_value(login_request, "address") {
                Some(address) => lookup_3pid(medium, address),
                None => Err(AuthError::MissingValue("address")),
            }
        }
        None => {
            match get_login_request_value(login_request, "user") {
                Some(user) => get_error!(db::get().lookup_user_by_user_id(user)),
                None => Err(AuthError::MissingValue("user")),
            }
        }
    }
}

// Get a login response for a user ID
fn get_login_response(user_id: &str) -> Result<LoginResponse, AuthError> {
    let home_server = try!(get_error!(db::get().lookup_home_server(user_id)));
    return Ok(LoginResponse {
        access_token: String::from("abcdef"),
        home_server: match home_server {
            Some(value) => value,
            None => "".to_string(),
        },
        user_id: user_id.to_string(),
        refresh_token: None,
    });
}

// Retrieve the login type string
fn get_login_type(login_request: &serde_json::Value) -> Option<String> {
    match get_login_request_value(login_request, "type") {
        Some(value) => Some(value.to_string()),
        None => None,
    }
}

static DUMMY_AUTH: &'static str = "m.login.dummy";

// Gets the login type, looks up the authentication function, and calls handle_authentication_request
pub fn authenticate(login_request: &serde_json::Value, internal: bool) -> Result<bool, AuthError> {
    match get_login_type(&login_request) {
        Some(login_type) => {
            if login_type == DUMMY_AUTH && internal {
                return Ok(true);
            }
            match AUTHENTICATION_METHODS.get(login_type.as_str()) {
                Some(authentication_method) => authentication_method(login_request),
                None => Err(AuthError::UnknownAuthMethod(login_type.to_owned())),
            }
        }
        None => Err(AuthError::MissingValue("login type")),
    }
}

fn get_error(status: Status,
             errcode: error::Errcode,
             error_string: &str)
             -> status::Custom<JSON<error::Error>> {
    status::Custom(status,
                   JSON(error::Error {
                       errcode: errcode,
                       error: error_string.to_string(),
                   }))
}

// REST endpoint to get the flows
#[get("/login")]
fn get_flows() -> JSON<serde_json::Value> {
    let mut flow = serde_json::Map::new();
    flow.insert("type".to_string(),
                serde_json::Value::String("m.login.password".to_string()));
    let mut value = serde_json::Map::new();
    value.insert("flows".to_string(),
                 serde_json::Value::Array(vec![serde_json::Value::Object(flow)]));
    return JSON(serde_json::Value::Object(value));
}

// REST authentication endpoint
#[post("/login", format="application/json", data="<login_request_json>")]
fn login(login_request_json: JSON<serde_json::Value>)
         -> Result<status::Custom<JSON<LoginResponse>>, status::Custom<JSON<error::Error>>> {
    let login_request = login_request_json.unwrap();
    match authenticate(&login_request, false) {
        Ok(true) => {
            match get_user_id(&login_request) {
                Ok(Some(user_id)) => {
                    match get_login_response(user_id.as_str()) {
                        Ok(login_response) => Ok(status::Custom(Status::Ok, JSON(login_response))),
                        Err(error) => Err(From::from(error)),
                    }
                }
                Ok(None) => {
                    Err(From::from(AuthError::SystemError("User ID not found".to_string())))
                }
                Err(error) => Err(From::from(error)),
            }
        }
        Ok(false) => {
            Err(get_error(Status::Forbidden,
                          error::Errcode::Forbidden,
                          "Authentication failed"))
        }
        Err(error) => Err(From::from(error)),
    }
}

// Mounts the routes required for this module
pub fn mount(rocket: rocket::Rocket) -> rocket::Rocket {
    return rocket.mount("/_matrix/client/r0", routes![get_flows, login]);
}

// Unit Tests
//

#[cfg(test)]
mod test {
    use super::error;
    use super::rocket;
    use super::LoginResponse;
    use rocket::http::{Status, Method};
    use rocket::http::ContentType;
    use rocket::testing::MockRequest;
    use serde_json;
    use std::collections::BTreeMap;
    use toml::Value;

    #[derive(Serialize, Debug)]
    struct LoginRequest<'r> {
        password: String,
        medium: Option<String>,
        #[serde(rename="type")]
        login_type: String,
        user: Option<&'r str>,
        address: Option<String>,
    }

    fn mock_db_config() -> BTreeMap<String, Value> {
        let mut table: BTreeMap<String, Value> = BTreeMap::new();
        table.insert("type".to_string(), Value::String("mock".to_string()));
        table
    }

    #[test]
    fn test_get_flows() {
        let rocket = rocket::ignite().mount("/_matrix/client/r0", routes![super::get_flows]);
        let table = mock_db_config();
        super::db::initialize(&Value::Table(table));

        let mut req = MockRequest::new(Method::Get, "/_matrix/client/r0/login");
        let mut response = req.dispatch_with(&rocket);

        assert_eq!(response.status(), Status::Ok);

        let body_str = response.body().and_then(|b| b.into_string());
        let json_response: serde_json::Value = serde_json::from_str(body_str.unwrap().as_str())
            .unwrap();
        let flows = json_response.as_object().unwrap().get("flows").unwrap().as_array().unwrap();
        assert_eq!(1, flows.len());
        let flow = flows[0].as_object().unwrap();
        assert_eq!("m.login.password",
                   flow.get("type").unwrap().as_str().unwrap());
    }

    fn login_with_password_request(user: Option<&str>,
                                   password: &str,
                                   login_type: &str)
                                   -> MockRequest {
        let login_request = LoginRequest {
            password: password.to_string(),
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
        let table = mock_db_config();
        super::db::initialize(&Value::Table(table));
        let mut req = MockRequest::new(Method::Post, "/_matrix/client/r0/login")
            .header(ContentType::JSON)
            .body("!2qwjoldskfi33903");
        let mut response = req.dispatch_with(&rocket);

        assert_eq!(response.status(), Status::BadRequest);

        let body_str = response.body().and_then(|b| b.into_string());
        assert_eq!(Some("{\"errcode\":\"M_BAD_JSON\",\"error\":\"Bad JSON\"}".to_string()),
                   body_str);
    }

    #[test]
    fn test_authenticate_not_found() {
        let rocket = super::super::mount();
        let table = mock_db_config();
        super::db::initialize(&Value::Table(table));
        let login_request = LoginRequest {
            password: "bar".to_string(),
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
        assert_eq!(Some("{\"errcode\":\"M_NOT_FOUND\",\"error\":\"Not Found\"}".to_string()),
                   body_str);
    }

    #[test]
    fn test_password_login_authenticated() {
        let rocket = super::super::mount();
        let table = mock_db_config();
        super::db::initialize(&Value::Table(table));
        let mut req = login_with_password_request(Some("foo"), "bar", "m.login.password");
        let mut response = req.dispatch_with(&rocket);

        assert_eq!(response.status(), Status::Ok);

        let body_str = response.body().and_then(|b| b.into_string());
        let login_response: LoginResponse = serde_json::from_str(body_str.unwrap().as_str())
            .unwrap();
        assert!(!login_response.access_token.is_empty());
        assert!(!login_response.home_server.is_empty());
        assert!(!login_response.user_id.is_empty());
    }

    #[test]
    fn test_password_login_failed_authentication() {
        let rocket = super::super::mount();
        let table = mock_db_config();
        super::db::initialize(&Value::Table(table));
        let mut req = login_with_password_request(Some("foo"), "baz", "m.login.password");
        let mut response = req.dispatch_with(&rocket);

        assert_eq!(response.status(), Status::Forbidden);

        let body_str = response.body().and_then(|b| b.into_string());
        let error: error::Error = serde_json::from_str(body_str.unwrap().as_str()).unwrap();
        assert_eq!(error.errcode, error::Errcode::Forbidden);
    }

    #[test]
    fn test_password_login_bad_login_type() {
        let rocket = super::super::mount();
        let table = mock_db_config();
        super::db::initialize(&Value::Table(table));
        let mut req = login_with_password_request(Some("foo"), "baz", "");
        let mut response = req.dispatch_with(&rocket);

        assert_eq!(response.status(), Status::BadRequest);

        let body_str = response.body().and_then(|b| b.into_string());
        let error: super::error::Error = serde_json::from_str(body_str.unwrap().as_str()).unwrap();
        assert_eq!(error.errcode, error::Errcode::BadJson);
    }

    #[test]
    fn test_password_login_no_user_id() {
        let rocket = super::super::mount();
        let table = mock_db_config();
        super::db::initialize(&Value::Table(table));
        let mut req = login_with_password_request(None, "baz", "m.login.password");
        let mut response = req.dispatch_with(&rocket);

        assert_eq!(response.status(), Status::BadRequest);

        let body_str = response.body().and_then(|b| b.into_string());
        let error: serde_json::Map<String, String> =
            serde_json::from_str(body_str.unwrap().as_str()).unwrap();
        assert_eq!("M_BAD_JSON", error.get("errcode").unwrap().as_str());
    }
}