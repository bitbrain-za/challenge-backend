use axum::{
    extract,
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Router,
};
use envcrypt::option_envc;
use http::Method;
use log::{debug, error, info, LevelFilter};
use scoreboard_db::{Db, Score};
use simple_logger::SimpleLogger;
use tower_http::cors::Any;
mod run;
use run::Submission;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    if cfg!(debug_assertions) {
        SimpleLogger::new()
            .with_level(LevelFilter::Debug)
            .init()
            .unwrap();
    } else {
        SimpleLogger::new()
            .with_level(LevelFilter::Info)
            .init()
            .unwrap();
    }
    let args = std::env::args().collect::<Vec<String>>();
    let mut port = 3000;
    for (i, arg) in args.iter().enumerate() {
        if arg == "-P" {
            if let Ok(p) = args
                .get(i + 1)
                .expect("-P must provide a port number")
                .parse::<u32>()
            {
                port = p;
            }
        }
    }

    info!("Checking DB credentials");
    let _ = match option_envc!("DB_PASSWORD") {
        Some(pass) => pass,
        None => {
            return Err(
                "This program needs to be compiled with the $DB_PASSWORD env variable set".into(),
            )
        }
    };

    let app = Router::new()
        .route("/submit/:id", post(post_run))
        .route("/scores/:id", get(get_scores))
        .layer(
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

    info!("Starting server");
    axum::Server::bind(&format!("0.0.0.0:{}", port).parse().unwrap())
        .serve(app.into_make_service())
        .await
        .unwrap();

    Ok(())
}

async fn get_scores(extract::Path(id): extract::Path<String>) -> impl IntoResponse {
    const MAX_SCORES: Option<usize> = Some(1000);
    debug!("get Scores");
    let db_pass = match option_env!("DB_PASSWORD") {
        Some(pass) => pass,
        None => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "This program needs to be compiled with the $DB_PASSWORD env variable set"
                    .to_string(),
            )
        }
    };

    let mut db = match Db::new("localhost", 3306, "code_challenge", db_pass, &id) {
        Ok(db) => db,
        Err(e) => {
            error!("Failed to connect to database: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to connect to database".to_string(),
            );
        }
    };
    let scores: Vec<Score> = match db.get_scores(MAX_SCORES) {
        Ok(s) => s,
        Err(e) => {
            error!("Failed to get scores: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to get scores".to_string(),
            );
        }
    };

    (StatusCode::OK, serde_json::to_string(&scores).unwrap())
}

async fn post_run(extract::Path(id): extract::Path<String>, body: String) -> impl IntoResponse {
    debug!("Post Run for challenge {}", id);

    debug!("body: {}", body);
    let run: Submission = serde_json::from_str(&body).unwrap();
    debug!("Run: {:?}", run);
    let res = run.run();
    (StatusCode::OK, serde_json::to_string(&res).unwrap())
}
