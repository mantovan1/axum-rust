use serde::{Deserialize, Serialize};
use sqlx::FromRow;

#[derive(Serialize, Deserialize)]
pub struct CreateUserSchema {
    pub name: String,
    pub email: String,
    pub password: String
}

#[derive(Deserialize, Serialize, Debug)]
pub struct User {
    pub id: i64,
    pub name: String,
    pub email: String,
    pub password: String
}

#[derive(Deserialize, Serialize, FromRow, Debug)]
pub struct UserResponse {
    pub id: i64,
    pub name: String,
    pub email: String
}

#[derive(Deserialize, Serialize, FromRow, Debug)]
pub struct Roles {
    pub id: i64,
    pub name: String
}

pub fn to_user_response(user: &User) -> UserResponse {
    UserResponse {
        id: user.id,
        name: user.name.clone(),
        email: user.email.clone()
    }
}