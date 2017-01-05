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

#[cfg(test)]
mod test {
    use super::rocket;
    use rocket::testing::MockRequest;
    use rocket::http::{Status, Method};

    #[test]
    fn test_versions() {
        let rocket = rocket::ignite().mount("/_matrix/client", routes![super::versions]);
        let mut req = MockRequest::new(Method::Get, "/_matrix/client/versions");
        let mut response = req.dispatch_with(&rocket);

        assert_eq!(response.status(), Status::Ok);

        let body_str = response.body().and_then(|b| b.into_string());
        assert_eq!(body_str, Some("{\"versions\":[\"r0.2.0\"]}".to_string()))
    }
}