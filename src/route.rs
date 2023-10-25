use std::sync::Arc;

use crate::handler::{get_scores, post_run};
use crate::login_handler::{login_user_handler, logout_handler, register_user_handler};

use crate::jwt_auth::auth;
use crate::AppState;

use axum::{
    middleware::{self},
    routing::{get, post},
    Router,
};

pub fn create_router(app_state: Arc<AppState>) -> Router {
    Router::new()
        .route("/api/auth/register", post(register_user_handler))
        .route("/api/auth/login", post(login_user_handler))
        .route(
            "/api/auth/logout",
            get(logout_handler)
                .route_layer(middleware::from_fn_with_state(app_state.clone(), auth)),
        )
        .route(
            "/api/game/submit",
            post(post_run).route_layer(middleware::from_fn_with_state(app_state.clone(), auth)),
        )
        .route("/api/game/scores/:id", get(get_scores))
        .with_state(app_state)
}