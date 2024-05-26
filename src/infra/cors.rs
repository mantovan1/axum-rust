use tower_http::cors::{Any, CorsLayer};
use http::{
    Method,
    header::{ACCESS_CONTROL_ALLOW_ORIGIN, CONTENT_TYPE, AUTHORIZATION, ACCEPT}
};

pub fn create_cors() -> CorsLayer {
    let cors = CorsLayer::new()
        .allow_methods(Any)
        .allow_origin(Any)
        .allow_headers([AUTHORIZATION, CONTENT_TYPE, ACCEPT, ACCESS_CONTROL_ALLOW_ORIGIN]);
    cors
}