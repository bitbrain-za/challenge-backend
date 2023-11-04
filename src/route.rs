use std::sync::Arc;

use crate::handler::{get_scores, post_binary, post_run};
use crate::login_handler::{
    login_user_handler, logout_handler, refresh_access_token_handler, register_user_handler,
};

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
        .route("/api/auth/refresh", get(refresh_access_token_handler))
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
            "/api/game/binary/:id",
            post(post_binary).route_layer(middleware::from_fn_with_state(app_state.clone(), auth)),
        )
        .with_state(app_state)
}
