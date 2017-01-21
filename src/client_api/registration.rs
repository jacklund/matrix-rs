use rocket;
use rocket::response::status;
use rocket::http::Status;
use rocket_contrib::JSON;
use serde_json;
use std::collections::BTreeMap;
use super::error;

#[derive(Serialize, Deserialize, Debug)]
struct RegistrationResponse {
    user_id: String,
    access_token: String,
    home_server: String,
    refresh_token: String,
}

fn some_or_error<T>(option: Option<T>,
                    status: Status,
                    errcode: error::Errcode,
                    error_str: &str)
                    -> Result<T, status::Custom<JSON<error::Error>>> {
    match option {
        Some(something) => Ok(something),
        None => {
            Err(status::Custom(status,
                               JSON(error::Error {
                                   errcode: errcode,
                                   error: error_str.to_string(),
                               })))
        }
    }
}

// REST authentication endpoint
#[allow(unused_variables)]
#[post("/register", format="application/json", data="<registration_request>")]
fn register
    (registration_request: JSON<serde_json::Value>)
     -> Result<status::Custom<JSON<RegistrationResponse>>, status::Custom<JSON<error::Error>>> {
    let request: &BTreeMap<String, serde_json::Value> =
        try!(some_or_error(registration_request.as_object(),
                           Status::BadRequest,
                           error::Errcode::BadJson,
                           "Bad JSON"));
    let user_id = try!(some_or_error(request.get("username"),
                                     Status::BadRequest,
                                     error::Errcode::InvalidParam,
                                     "No username specified"));
    let password = try!(some_or_error(request.get("password"),
                                      Status::BadRequest,
                                      error::Errcode::InvalidParam,
                                      "No password specified"));
    let auth = try!(some_or_error(request.get("auth"),
                                  Status::BadRequest,
                                  error::Errcode::Unauthorized,
                                  "No auth specified"));
    let login_response = try!(super::login::authenticate(auth, true));
    Ok(status::Custom(Status::Ok,
                      JSON(RegistrationResponse {
                          user_id: "foo".to_string(),
                          access_token: "bar".to_string(),
                          home_server: "baz".to_string(),
                          refresh_token: "foobar".to_string(),
                      })))
}

// Mounts the routes required for this module
pub fn mount(rocket: rocket::Rocket) -> rocket::Rocket {
    return rocket.mount("/_matrix/client/r0", routes![register]);
}

// Unit tests
//

#[cfg(test)]
mod test {
    use rocket::http::{ContentType, Method, Status};
    use rocket::testing::MockRequest;
    use serde_json;
    use std::collections::BTreeMap;
    use super::super::super::db;
    use super::super::error;
    use toml::Value;

    fn mock_db_config() -> BTreeMap<String, Value> {
        let mut table: BTreeMap<String, Value> = BTreeMap::new();
        table.insert("type".to_string(), Value::String("mock".to_string()));
        table
    }

    #[test]
    fn test_register_bad_json() {
        let rocket = super::super::mount();
        let table = mock_db_config();
        db::initialize(&Value::Table(table));

        let mut req = MockRequest::new(Method::Post, "/_matrix/client/r0/register")
            .header(ContentType::JSON)
            .body("");
        let mut response = req.dispatch_with(&rocket);

        assert_eq!(response.status(), Status::BadRequest);

        let body_str = response.body().and_then(|b| b.into_string());
        assert!(body_str.is_some());
        let error: error::Error = serde_json::from_str(body_str.unwrap().as_ref()).expect("Ooops!");
        assert_eq!(error.errcode, error::Errcode::BadJson);
        assert_eq!(error.error, "Bad JSON");
    }

    #[test]
    fn test_register() {
        let rocket = super::super::mount();
        let table = mock_db_config();
        db::initialize(&Value::Table(table));

        let mut req = MockRequest::new(Method::Post, "/_matrix/client/r0/register")
            .header(ContentType::JSON)
            .body("{\"username\": \"foo\", \"password\": \"bar\", \"auth\": { \"type\": \
                   \"m.login.dummy\" }}");
        let mut response = req.dispatch_with(&rocket);

        assert_eq!(response.status(), Status::Ok);

        let body_str = response.body().and_then(|b| b.into_string());
        assert!(body_str.is_some());
        println!("{:?}", body_str);
        let value: serde_json::Value = serde_json::from_str(body_str.unwrap().as_str()).unwrap();
        let response = value.as_object().unwrap();
        assert_eq!(response["user_id"].as_str().unwrap(), "foo");
        assert_eq!(response["access_token"].as_str().unwrap(), "bar");
        assert_eq!(response["home_server"].as_str().unwrap(), "baz");
        assert_eq!(response["refresh_token"].as_str().unwrap(), "foobar");
    }
}