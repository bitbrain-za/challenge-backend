use std::sync::Arc;

use crate::handler::{get_scores, post_binary, post_run};
use crate::login_handler::{
    cookie_test_handler, forgot_password_handler, login_user_handler, logout_handler,
    refresh_access_token_handler, register_user_handler, reset_password_handler,
    verify_email_handler,
};

use crate::jwt_auth::auth;
use crate::AppState;
use axum::{
    extract::DefaultBodyLimit,
    middleware::{self},
    routing::{get, post},
    Router,
};

const CONTENT_LENGTH_LIMIT: usize = 20 * 1024 * 1024;

pub fn create_router(app_state: Arc<AppState>) -> Router {
    Router::new()
        .route("/api/test", get(cookie_test_handler))
        .route("/api/auth/register", post(register_user_handler))
        .route("/api/auth/login", post(login_user_handler))
        .route("/api/auth/refresh", get(refresh_access_token_handler))
        .route(
            "/api/auth/verifyemail/:verification_code",
            get(verify_email_handler),
        )
        .route("/api/auth/forgotpassword", post(forgot_password_handler))
        .route(
            "/api/auth/resetpassword/:password_reset_token",
            post(reset_password_handler),
        )
        .route(
            "/api/auth/logout",
            post(logout_handler)
                .route_layer(middleware::from_fn_with_state(app_state.clone(), auth)),
        )
        .route(
            "/api/game/submit",
            post(post_run).route_layer(middleware::from_fn_with_state(app_state.clone(), auth)),
        )
        // .route("/api/game/scores/:id", get(get_scores))
        .route(
            "/api/game/scores/:id",
            get(get_scores).route_layer(middleware::from_fn_with_state(app_state.clone(), auth)),
        )
        .route(
            "/api/game/binary",
            post(post_binary).route_layer(middleware::from_fn_with_state(app_state.clone(), auth)),
        )
        .layer(DefaultBodyLimit::max(CONTENT_LENGTH_LIMIT))
        .with_state(app_state)
}
