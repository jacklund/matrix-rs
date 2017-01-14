use regex::Regex;
use std::fmt;
use std::collections::HashMap;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

// Macro to construct the Errcode enum, along with its custom JSON (de)seriialization
macro_rules! enum_str {
    ($name:ident { $($variant:ident, )* }) => {
        #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
        pub enum $name {
            $($variant,)*
        }

        // Function to convert an Errcode to a string like "M_GUEST_ACCESS_FORBIDDEN"
        fn as_string(errcode: Errcode) -> String {
            let re = Regex::new(r"([a-z])([A-Z])").unwrap();
            "M_".to_string() + re.replace_all(errcode.to_string().as_str(), r"${1}_${2}").to_uppercase().as_str()
        }

        // Maps to convert from Errcode <=> String
        lazy_static! {
            static ref FROM_STRING: HashMap<String, Errcode> = {
                let mut m = HashMap::new();
                $(m.insert(as_string($name::$variant), $name::$variant);)*
                m
            };

            static ref TO_STRING: HashMap<Errcode, String> = {
                let mut m = HashMap::new();
                $(m.insert($name::$variant, as_string($name::$variant));)*
                m
            };
        }

        // Convert from string to Errcode
        fn from_string(string: &str) -> Option<&Errcode> {
            FROM_STRING.get(string)
        }

        // Convert from Errcode to String
        fn to_string<'r>(errcode: &Errcode) -> Option<&'r String> {
            TO_STRING.get(errcode)
        }

        // JSON serialization
        impl Serialize for Errcode {
            fn serialize<S>(&self, serializer: &mut S) -> Result<(), S::Error>
                where S: Serializer,
            {
                // Serialize the enum as a string.
                match to_string(self) {
                    Some(string) => serializer.serialize_str(string),
                    None         => Err(::serde::ser::Error::invalid_value(
                                    &format!("unknown {} variant: {}",
                                    stringify!(Errcode), stringify!(self)))),
                }
            }
        }

        // JSON Deserialization
        impl Deserialize for Errcode {
            fn deserialize<D>(deserializer: &mut D) -> Result<Self, D::Error>
                where D: Deserializer,
            {
                struct Visitor;

                impl ::serde::de::Visitor for Visitor {
                    type Value = Errcode;

                    fn visit_str<E>(&mut self, value: &str) -> Result<Errcode, E>
                        where E: ::serde::de::Error,
                    {
                        match from_string(value) {
                            Some(errcode) => Ok(errcode.to_owned()),
                            None          => Err(E::invalid_value(
                                &format!("unknown {} variant: {}",
                                stringify!(Errcode), value))),
                        }
                    }
                }

                // Deserialize the enum from a string.
                deserializer.deserialize_str(Visitor)
            }
        }
    }
}

// Make the errcode enum
enum_str!(Errcode {
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
});

// Print the errcode as string
impl fmt::Display for Errcode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

// Error struct returned by REST endpoints
#[derive(Serialize, Deserialize, Debug)]
pub struct Error{
    pub errcode : Errcode,
    pub error : String,
}

//
// Unit tests
//

#[cfg(test)]
mod test {
    use super::Errcode;
    use serde_test::{Error, Token, assert_de_tokens_error, assert_tokens};

    #[test]
    fn test_errcode_serialization() {
        let errcode: Errcode = Errcode::GuestAccessForbidden;

        assert_tokens(&errcode, &[Token::Str("M_GUEST_ACCESS_FORBIDDEN")]);
    }

    #[test]
    fn test_errcode_printing() {
        assert_eq!("Forbidden", Errcode::Forbidden.to_string());
    }

    #[test]
    fn test_deserialize_bad_string() {
        assert_de_tokens_error::<Errcode>(&[Token::Str("BAD_STRING")], Error::InvalidValue("unknown Errcode variant: BAD_STRING".to_string()));
    }
}