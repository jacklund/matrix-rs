#[allow(dead_code)]
pub mod errcodes {
    pub const UNRECOGNIZED : &'static str = "M_UNRECOGNIZED";
    pub const UNAUTHORIZED : &'static str = "M_UNAUTHORIZED";
    pub const FORBIDDEN : &'static str = "M_FORBIDDEN";
    pub const BAD_JSON : &'static str = "M_BAD_JSON";
    pub const NOT_JSON : &'static str = "M_NOT_JSON";
    pub const USER_IN_USE : &'static str = "M_USER_IN_USE";
    pub const ROOM_IN_USE : &'static str = "M_ROOM_IN_USE";
    pub const BAD_PAGINATION : &'static str = "M_BAD_PAGINATION";
    pub const BAD_STATE : &'static str = "M_BAD_STATE";
    pub const UNKNOWN : &'static str = "M_UNKNOWN";
    pub const NOT_FOUND : &'static str = "M_NOT_FOUND";
    pub const MISSING_TOKEN : &'static str = "M_MISSING_TOKEN";
    pub const UNKNOWN_TOKEN : &'static str = "M_UNKNOWN_TOKEN";
    pub const GUEST_ACCESS_FORBIDDEN : &'static str = "M_GUEST_ACCESS_FORBIDDEN";
    pub const LIMIT_EXCEEDED : &'static str = "M_LIMIT_EXCEEDED";
    pub const CAPTCHA_NEEDED : &'static str = "M_CAPTCHA_NEEDED";
    pub const CAPTCHA_INVALID : &'static str = "M_CAPTCHA_INVALID";
    pub const MISSING_PARAM : &'static str = "M_MISSING_PARAM";
    pub const INVALID_PARAM : &'static str = "M_INVALID_PARAM";
    pub const TOO_LARGE : &'static str = "M_TOO_LARGE";
    pub const EXCLUSIVE : &'static str = "M_EXCLUSIVE";
    pub const THREEPID_AUTH_FAILED : &'static str = "M_THREEPID_AUTH_FAILED";
    pub const THREEPID_IN_USE : &'static str = "M_THREEPID_IN_USE";
    pub const THREEPID_NOT_FOUND : &'static str = "M_THREEPID_NOT_FOUND";
    pub const INVALID_USERNAME : &'static str = "M_INVALID_USERNAME";
    pub const SERVER_NOT_TRUSTED : &'static str = "M_SERVER_NOT_TRUSTED";
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Error{
    pub errcode : String,
    pub error : String,
}