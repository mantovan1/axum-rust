use axum::{
    async_trait,
    routing::{get, post},
    http::{request::Parts, StatusCode},
    Extension, Json, Router,
    extract::{FromRequestParts, Path},
    response::{IntoResponse, Response},
    RequestPartsExt
};
use axum_extra::{
    headers::{authorization::Bearer, Authorization},
    TypedHeader,
};
use http::{
    Method,
    header::{ACCESS_CONTROL_ALLOW_ORIGIN, CONTENT_TYPE, AUTHORIZATION, ACCEPT}
};
use tower_http::cors::{Any, CorsLayer};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::sync::Mutex;
use std::{
    fmt::Display,
    sync::Arc
};

use sqlx::{sqlite::SqlitePool, FromRow};
use jsonwebtoken::{decode, encode, Validation, Header, DecodingKey, EncodingKey};
use chrono::Utc;
use pwhash::bcrypt;

#[tokio::main]
async fn main() {
    let database_url = "sqlite://database.sqlite";
    let pool = SqlitePool::connect(&database_url)
        .await
        .expect("Failed to create pool");

    let shared_pool = Arc::new(Mutex::new(pool));
    let cors = CorsLayer::new()
        .allow_methods(Any)
        .allow_origin(Any)
        .allow_headers([AUTHORIZATION, CONTENT_TYPE, ACCEPT, ACCESS_CONTROL_ALLOW_ORIGIN]);
    let app : Router = Router::new()
        .route("/user", get(list_users))
        .route("/user", post(create_user))
        .route("/user/roles/:id", get(list_user_roles))
        .route("/user/auth", post(login))
        .route("/blog", post(create_blog))
        .route("/blog", get(list_blogs))
        .layer(cors)
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
) -> Result<Json<Vec<String>>, StatusCode> {
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

    let names: Vec<String> = roles.into_iter().map(|role| role.name).collect();
    Ok(Json(names))
}

pub async fn create_user(
    claims: Claims,
    Extension(pool): Extension<Arc<Mutex<SqlitePool>>>,
    Json(body): Json<CreateUserSchema>
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    if !claims.roles.contains(&String::from("Admin")) {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({"status": "error","message": format!("{:?}", "err")})),
        ));
    }
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

    if !verify_result {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({"status": "error", "message": "Invalid login credentials"})),
        ));
    }

    let roles = sqlx::query_as::<_, Roles>(
        r#"
        SELECT roles.id, roles.name
        FROM roles
        JOIN user_roles
        ON user_roles.role_id = roles.id
        WHERE user_roles.user_id = ?
        "#
    )
    .bind(&user.id)
    .fetch_all(&*pool)
    .await
    .unwrap();

    let role_names: Vec<String> = vec![roles.into_iter().map(|role| role.name).collect()];

    let token = generate_jwt(&user, &role_names).await.map_err(|e| {
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
    roles: Vec<String>,
    iss: String,
    exp: usize,
}

fn hash(password: &str) -> Result<String, pwhash::error::Error> {
    bcrypt::hash(password)
}

async fn generate_jwt(user: &User, role_names: &Vec<String>) -> Result<String, jsonwebtoken::errors::Error> {
    let claims = Claims {
        sub: user.email.clone(),
        roles: role_names.clone(),
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

impl Display for Claims {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Email: {}\nCompany: {}", self.sub, self.iss)
    }
}

#[async_trait]
impl<S> FromRequestParts<S> for Claims
where
    S: Send + Sync,
{
    type Rejection = AuthError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        // Extract the token from the authorization header
        let TypedHeader(Authorization(bearer)) = parts
            .extract::<TypedHeader<Authorization<Bearer>>>()
            .await
            .map_err(|_| AuthError::InvalidToken)?;
        // Decode the user data
        let token_data = decode::<Claims>(bearer.token(), &DecodingKey::from_secret("secret".as_ref()), &Validation::default())
            .map_err(|_| AuthError::InvalidToken)?;

        Ok(token_data.claims)
    }
}

//blog

#[derive(Serialize, Deserialize, Debug)]
pub struct CreateBlogSchema {
    title: String,
    slug: String,
    content: String,
}

#[derive(Serialize, FromRow, Deserialize, Debug)]
pub struct Blog {
    id: i64,
    title: String,
    slug: String,
    content: String,
}

pub async fn create_blog(
    claims: Claims,
    Extension(pool): Extension<Arc<Mutex<SqlitePool>>>,
    Json(body): Json<CreateBlogSchema>
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    if !claims.roles.contains(&String::from("Admin")) {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({"status": "error","message": format!("{:?}", "err")})),
        ));
    }

    let pool = pool.lock().await;
    let query_result = sqlx::query(r#"INSERT INTO blogs (title, slug, content) VALUES (?, ?, ?)"#)
        .bind(body.title.to_string())
        .bind(body.slug.to_string())
        .bind(body.content.to_string())
        .execute(&*pool)
        .await
        .map_err(|err: sqlx::Error| err.to_string());
    
    // Duplicate err check
    if let Err(err) = query_result {
        if err.contains("Duplicate entry") {
            let error_response = serde_json::json!({
                "status": "error",
                "message": "Blog already exists",
            });
            return Err((StatusCode::CONFLICT, Json(error_response)));
        }

        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"status": "error","message": format!("{:?}", err)})),
        ));
    }

    // Get insereted note by ID
    let blog = sqlx::query_as!(Blog, r#"SELECT * FROM blogs WHERE slug = ?"#, body.slug)
        .fetch_one(&*pool)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"status": "error","message": format!("{:?}", e)})),
            )
        })?;

    let blog_response = serde_json::json!({
            "status": "success",
            "data": serde_json::json!({
                "blog": &blog
        })
    });

    Ok(Json(blog_response))
}

pub async fn list_blogs(
    Extension(pool): Extension<Arc<Mutex<SqlitePool>>>
) -> Json<Vec<Blog>> {
    let pool = pool.lock().await;
    let blogs = sqlx::query_as::<_, Blog>(
        r#"
        SELECT *
        FROM blogs
        "#
    )
    .fetch_all(&*pool)
    .await
    .unwrap();

    Json(blogs)
}