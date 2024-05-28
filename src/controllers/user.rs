use sqlx::sqlite::SqlitePool;
use axum::{Extension, Json, http::StatusCode, extract::Path, response::IntoResponse};
use tokio::sync::Mutex;
use std::{env, sync::Arc};
use serde_json::json;
use mail_send::SmtpClientBuilder;
use mail_builder::MessageBuilder;
use dotenv::dotenv;

use crate::{
    modules::{
        hash::hash,
        rand::generate_random_string
    },
    schemas::{
        user::{CreateUserSchema, User, UserVerificationList, UserRole, to_user_response},
    }
};

pub async fn create_user(
    Extension(pool): Extension<Arc<Mutex<SqlitePool>>>,
    Extension(user_verification_list): Extension<Arc<Mutex<UserVerificationList>>>,
    Json(body): Json<CreateUserSchema>
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let mut user_verification_list = user_verification_list.lock().await;
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

    let rand = generate_random_string(10);
    user_verification_list.add_verification(rand.clone(), user.id);
    dotenv().ok();
    let email = env::var("EMAIL_USER").expect("not set");
    let pass = env::var("EMAIL_PASS").expect("not set");
    
    let message = MessageBuilder::new()
    .from(("Blog", &email[..]))
    .to(vec![
        ("User", &user.email[..])  // Convert user.email to &str
    ])
    .subject("Hi!")
    .html_body(format!("<a href=\"http://localhost:3000/verify/{}\">verificar</a>", rand))
    .text_body("Hello world!");

    // Connect to the SMTP submissions port, upgrade to TLS and
    // authenticate using the provided credentials.

    SmtpClientBuilder::new("smtp.umbler.com", 587)
        .implicit_tls(false)
        .credentials((&email[..], &pass[..]))
        .connect()
        .await
        .unwrap()
        .send(message)
        .await
        .unwrap();

    let user_response = json!({
        "status": "success",
        "data": {
            "user": to_user_response(&user),
            "rand": &rand
        }
    });

    Ok(Json(user_response))
}

pub async fn verify(
    Path(rand): Path<String>,
    Extension(user_verification_list): Extension<Arc<Mutex<UserVerificationList>>>,
    Extension(pool): Extension<Arc<Mutex<SqlitePool>>>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let user_verification_list = user_verification_list.lock().await;
    let id = user_verification_list.get_id(&rand);

    if id.is_none() {
        return Err((
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"status": "error", "message": "Verification token not found"})),
        ));
    }
    let id = id.unwrap();

    let pool = pool.lock().await;
    let query_result = sqlx::query(r#"INSERT INTO user_roles (user_id, role_id) VALUES (?, ?)"#)
        .bind(id)
        .bind(2)
        .execute(&*pool)
        .await
        .map_err(|err: sqlx::Error| err.to_string());

    // Duplicate err check
    if let Err(err) = query_result {
        if err.contains("Duplicate entry") {
            let error_response = serde_json::json!({
                "status": "error",
                "message": "User role already exists",
            });
            return Err((StatusCode::CONFLICT, Json(error_response)));
        }

        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"status": "error","message": format!("{:?}", err)})),
        ));
    }

    // Get inserted note by ID
    let user_role = sqlx::query_as!(
        UserRole,
        r#"SELECT * FROM user_roles WHERE user_id = ?"#,
        id
    )
    .fetch_one(&*pool)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"status": "error","message": format!("{:?}", e)})),
        )
    })?;

    Ok(Json(user_role))
}
