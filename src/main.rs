use axum::{Extension, Router};
use std::sync::Arc;
use tokio::sync::Mutex;
use sqlx::sqlite::SqlitePool;
use rust_api::infra::{cors, routes};

#[tokio::main]
async fn main() {
    let cors = cors::create_cors();
    let database_url = "sqlite://database.sqlite";
    let pool = SqlitePool::connect(&database_url)
        .await
        .expect("Failed to create pool");

    let shared_pool = Arc::new(Mutex::new(pool));
        let app : Router = routes::create_router()
        .layer(cors)
        .layer(Extension(shared_pool));    

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}