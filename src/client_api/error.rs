#[derive(Serialize, Deserialize, Debug)]
pub struct Error{
    pub errcode : String,
    pub error : String,
}