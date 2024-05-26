use axum::{Router, routing::{get, post}};
use crate::modules::{
    auth_controller::auth,
    blog_controller::{create_blog, list_blogs, find_blog},
    user_controller::{create_user, verify}
};

pub fn create_router() -> Router {
    let app : Router = Router::new()
        .route("/auth", post(auth))
        .route("/verify/:rand", get(verify))
        .route("/blog", post(create_blog))
        .route("/blog", get(list_blogs))
        .route("/blog/:slug", get(find_blog))
        .route("/user", post(create_user));
    app
}