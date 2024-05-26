use serde::{Deserialize, Serialize};
use sqlx::FromRow;

#[derive(Serialize, Deserialize, Debug)]
pub struct CreateBlogSchema {
    pub title: String,
    pub slug: String,
    pub content: String,
    pub thumbnail: String
}

#[derive(Serialize, FromRow, Deserialize, Debug)]
pub struct Blog {
    pub id: i64,
    pub title: String,
    pub slug: String,
    pub content: String,
    pub thumbnail: String
}