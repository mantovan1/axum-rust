use sqlx::sqlite::SqlitePool;
use axum::{Extension, Json, http::StatusCode, extract::Path, response::IntoResponse};
use tokio::sync::Mutex;
use std::sync::Arc;
use serde_json::json;

use crate::models::{
    user_schema::{CreateUserSchema, User, to_user_response},
    claims_schema::Claims
};
use crate::modules::hash_usecase::hash;

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