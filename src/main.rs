use axum::{
    routing::{get, post},
    http::StatusCode,
    Extension, Json, Router,
    extract::Path,
    response::{IntoResponse, Response}
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::sync::Mutex;
use std::sync::Arc;
use sqlx::{sqlite::SqlitePool, FromRow};

use jsonwebtoken::{encode, Validation, Header, EncodingKey};
use chrono::Utc;
use pwhash::bcrypt;

#[tokio::main]
async fn main() {
    let database_url = "sqlite://database.sqlite";
    let pool = SqlitePool::connect(&database_url)
        .await
        .expect("Failed to create pool");

    let shared_pool = Arc::new(Mutex::new(pool));
    let app : Router = Router::new()
        .route("/user", get(list_users))
        .route("/user", post(create_user))
        .route("/user/roles/:id", get(list_user_roles))
        .route("/user/auth", post(login))
        .layer(Extension(shared_pool));    

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}


async fn list_users(
    Extension(pool): Extension<Arc<Mutex<SqlitePool>>>
) -> Result<Json<Vec<UserResponse>>, StatusCode> {
    let pool = pool.lock().await;
   
    let users = sqlx::query_as::<_, UserResponse>(
        r#"
        SELECT users.id, users.name, users.email
        FROM users
        "#
    )
    .fetch_all(&*pool)
    .await
    .unwrap();

    Ok(Json(users))
}

async fn list_user_roles(
    Extension(pool): Extension<Arc<Mutex<SqlitePool>>>,
    Path(id): Path<i64>
) -> Result<Json<Vec<Roles>>, StatusCode> {
    let pool = pool.lock().await;
   
    let roles = sqlx::query_as::<_, Roles>(
        r#"
        SELECT roles.id, roles.name
        FROM roles
        JOIN user_roles
        ON user_roles.role_id = roles.id
        WHERE user_roles.user_id = ?
        "#
    )
    .bind(&id)
    .fetch_all(&*pool)
    .await
    .unwrap();

    Ok(Json(roles))
}

pub async fn create_user(
    Extension(pool): Extension<Arc<Mutex<SqlitePool>>>,
    Json(body): Json<CreateUserSchema>
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let pool = pool.lock().await;
    let password = hash(&body.password).expect("something went wrong");
    let query_result = sqlx::query(r#"INSERT INTO users (name, email, password) VALUES (?, ?, ?)"#)
        .bind(body.name.to_string())
        .bind(body.email.to_string())
        .bind(password)
        .execute(&*pool)
        .await
        .map_err(|err| err.to_string());
    
    if let Err(err) = query_result {
        if err.contains("UNIQUE constraint failed") {
            let error_response = json!({
                "status": "error",
                "message": "User already exists",
            });
            return Err((StatusCode::CONFLICT, Json(error_response)));
        }

        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"status": "error","message": format!("{:?}", err)})),
        ));
    }

    let user = sqlx::query_as!(User, r#"SELECT id, name, email, password FROM users WHERE email = ?"#, body.email)
        .fetch_one(&*pool)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"status": "error","message": format!("{:?}", e)})),
            )
        })?;

    let user_response = json!({
        "status": "success",
        "data": {
            "user": to_user_response(&user)
        }
    });

    Ok(Json(user_response))
}

pub async fn login(
    Extension(pool): Extension<Arc<Mutex<SqlitePool>>>,
    Json(body): Json<UserLoginSchema>
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let pool = pool.lock().await;

    let user = sqlx::query_as!(User, r#"SELECT id, name, email, password FROM users WHERE email = ?"#, body.email)
    .fetch_one(&*pool)
    .await
    .map_err(|_| {
        (
            StatusCode::UNAUTHORIZED,
            Json(json!({"status": "error", "message": "Invalid login credentials"})),
        )
    })?;

    let verify_result = bcrypt::verify(&body.password, &user.password);

    if (!verify_result) {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({"status": "error", "message": "Invalid login credentials"})),
        ));
    }

    let token = generate_jwt(&user).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"status": "error","message": format!("Token generation error: {:?}", e)})),
        )
    })?;

    let response = json!({
        "status": "success",
        "data": {
            "user": to_user_response(&user),
            "token": token
        }
    });
    Ok(Json(response))
}

#[derive(Deserialize, Serialize, Debug)]
struct User {
    id: i64,
    name: String,
    email: String,
    password: String
}

#[derive(Deserialize, Serialize, FromRow, Debug)]
struct UserResponse {
    id: i64,
    name: String,
    email: String
}

#[derive(Deserialize, Serialize, FromRow, Debug)]
struct Roles {
    id: i64,
    name: String
}

#[derive(Serialize, Deserialize)]
pub struct CreateUserSchema {
    name: String,
    email: String,
    password: String
}

#[derive(Deserialize, Serialize, Debug)]
struct UserLoginSchema {
    email: String,
    password: String
}


#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    iss: String,
    exp: usize,
}

fn hash(password: &str) -> Result<String, pwhash::error::Error> {
    bcrypt::hash(password)
}

async fn generate_jwt(user: &User) -> Result<String, jsonwebtoken::errors::Error> {
    let claims = Claims {
        sub: user.email.clone(),
        iss: "issuer".to_string(),
        exp: (Utc::now() + chrono::Duration::hours(1)).timestamp() as usize,
    };

    let token = encode(&Header::default(), &claims, &EncodingKey::from_secret("secret".as_ref()))?;
    Ok(token)
}

fn to_user_response(user: &User) -> UserResponse {
    UserResponse {
        id: user.id,
        name: user.name.clone(),
        email: user.email.clone()
    }
}

#[derive(Debug)]
enum AuthError {
    WrongCredentials,
    MissingCredentials,
    TokenCreation,
    InvalidToken,
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            AuthError::WrongCredentials => (StatusCode::UNAUTHORIZED, "Wrong credentials"),
            AuthError::MissingCredentials => (StatusCode::BAD_REQUEST, "Missing credentials"),
            AuthError::TokenCreation => (StatusCode::INTERNAL_SERVER_ERROR, "Token creation error"),
            AuthError::InvalidToken => (StatusCode::BAD_REQUEST, "Invalid token"),
        };
        let body = Json(json!({
            "error": error_message,
        }));
        (status, body).into_response()
    }
}