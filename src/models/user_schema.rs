use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use std::collections::HashMap;

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

#[derive(Deserialize, Serialize, Debug)]
pub struct CreateUserRoleSchema {
    pub user_id: i64,
    pub role_id: i64
}

#[derive(Deserialize, Serialize, FromRow, Debug)]
pub struct UserRole {
    pub user_id: i64,
    pub role_id: i64
}

pub fn to_user_response(user: &User) -> UserResponse {
    UserResponse {
        id: user.id,
        name: user.name.clone(),
        email: user.email.clone()
    }
}

//user confirmation

#[derive(Serialize, Deserialize, Debug)]
pub struct UserVerificationList {
    pub verifications: HashMap<String, i64>,
}

impl UserVerificationList {
    pub fn new() -> Self {
        UserVerificationList {
            verifications: HashMap::new(),
        }
    }

    pub fn add_verification(&mut self, token: String, id: i64) {
        self.verifications.insert(token, id);
    }

    pub fn get_id(&self, token: &str) -> Option<&i64> {
        self.verifications.get(token)
    }

    pub fn remove_verification(&mut self, token: &str) {
        self.verifications.remove(token);
    }
}
