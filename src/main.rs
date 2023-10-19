use axum::{
    extract,
    http::StatusCode,
    response::{IntoResponse, Json, Response},
    routing::{get, patch, post},
    Router,
};
use http::Method;
use log::{debug, error, info, warn, LevelFilter};
use simple_logger::SimpleLogger;
use systemd_journal_logger::JournalLog;
use tower_http::cors::Any;

#[tokio::main]
async fn main() {
    if cfg!(debug_assertions) {
        SimpleLogger::new()
            .with_level(LevelFilter::Debug)
            .init()
            .unwrap();
    } else {
        JournalLog::new()
            .unwrap()
            .with_extra_fields(vec![("VERSION", env!("CARGO_PKG_VERSION"))])
            .with_syslog_identifier("foo".to_string())
            .install()
            .unwrap();
        log::set_max_level(LevelFilter::Info);
    }

    let app = Router::new().route("/scores", get(get_scores)).layer(
        tower_http::cors::CorsLayer::new()
            .allow_methods([
                Method::GET,
                Method::POST,
                Method::PUT,
                Method::PATCH,
                Method::DELETE,
                Method::OPTIONS,
            ])
            .allow_origin(Any)
            .allow_headers(Any),
    );

    axum::Server::bind(&"0.0.0.0:3000".parse().unwrap())
        .serve(app.into_make_service())
        .await
        .unwrap();
}

async fn get_scores() -> impl IntoResponse {
    debug!("get Self");
    (StatusCode::OK, "Hello World".to_string())
}
