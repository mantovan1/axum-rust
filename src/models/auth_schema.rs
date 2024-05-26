use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize, Debug)]
pub struct AuthSchema {
    pub email: String,
    pub password: String
}