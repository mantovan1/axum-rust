use sqlx::sqlite::SqlitePool;
use axum::{Extension, Json, http::StatusCode, extract::Path, response::IntoResponse};
use tokio::sync::Mutex;
use std::sync::Arc;
use serde_json::json;

use crate::schemas::{
    blog::{Blog, CreateBlogSchema},
    claims::Claims
};

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
    let query_result = sqlx::query(r#"INSERT INTO blogs (title, slug, content, thumbnail) VALUES (?, ?, ?, ?)"#)
        .bind(body.title.to_string())
        .bind(body.slug.to_string())
        .bind(body.content.to_string())
        .bind(body.thumbnail.to_string())
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

pub async fn find_blog(
    Path(slug): Path<String>,
    Extension(pool): Extension<Arc<Mutex<SqlitePool>>>
) -> Json<Blog> {
    let pool = pool.lock().await;
    
    let blog = sqlx::query_as!(Blog, r#"SELECT * FROM blogs WHERE slug = ?"#, slug)
    .fetch_one(&*pool)
    .await
    .expect("not found");   

    Json(blog)
}

pub async fn list_blogs(
    Extension(pool): Extension<Arc<Mutex<SqlitePool>>>
) -> Json<Vec<Blog>> {
    let pool = pool.lock().await;
    let blogs = sqlx::query_as::<_, Blog>(
        r#"
        SELECT *
        FROM blogs
        ORDER BY created_at DESC
        "#
    )
    .fetch_all(&*pool)
    .await
    .unwrap();

    Json(blogs)
}