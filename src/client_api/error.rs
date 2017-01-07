use regex::Regex;
use std::fmt;

#[allow(dead_code)]
#[derive(Debug, Deserialize, PartialEq, Serialize)]
pub enum Errcode {
    Unrecognized,
    Unauthorized,
    Forbidden,
    BadJson,
    NotJson,
    UserInUse,
    RoomInUse,
    BadPagination,
    BadState,
    Unknown,
    NotFound,
    MissingToken,
    UnknownToken,
    GuestAccessForbidden,
    LimitExceeded,
    CaptchaNeeded,
    CaptchaInvalid,
    MissingParam,
    InvalidParam,
    TooLarge,
    Exclusive,
    ThreepidAuthFailed,
    ThreepidNotInUse,
    ThreepidNotFound,
    InvalidUsername,
    ServerNotTrusted,
}

impl Errcode {
    pub fn to_snake_case(&self) -> String {
        let re = Regex::new(r"([a-z])([A-Z])").unwrap();
        re.replace_all(self.to_string().as_str(), r"${1}_${2}").to_lowercase()
    }

    pub fn as_error_code_string(&self) -> String {
        "M_".to_string() + &self.to_snake_case().to_uppercase()
    }
}

impl fmt::Display for Errcode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Error{
    pub errcode : Errcode,
    pub error : String,
}

#[cfg(test)]
mod test {
    use super::Errcode;

    #[test]
    fn test_snake_case() {
        assert_eq!("guest_access_forbidden".to_string(), Errcode::GuestAccessForbidden.to_snake_case());
    }

    #[test]
    fn test_as_error_code_string() {
        assert_eq!("M_GUEST_ACCESS_FORBIDDEN".to_string(), Errcode::GuestAccessForbidden.as_error_code_string());
    }
}