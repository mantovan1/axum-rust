use sqlx::sqlite::SqlitePool;
use axum::{Extension, Json, http::StatusCode};
use tokio::sync::Mutex;
use std::sync::Arc;
use serde_json::json;
use pwhash::bcrypt;

use crate::models::{
    auth_schema::AuthSchema,
    user_schema::{User, Roles, to_user_response}
};
use crate::modules::jwt_usecase::generate_jwt;

pub async fn auth(
    Extension(pool): Extension<Arc<Mutex<SqlitePool>>>,
    Json(body): Json<AuthSchema>
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