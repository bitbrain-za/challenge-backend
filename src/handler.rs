use crate::run::Submission;
use axum::{extract, http::StatusCode, response::IntoResponse};
use log::{debug, error};
use scoreboard_db::{Db, Score};

pub async fn get_scores(extract::Path(id): extract::Path<String>) -> impl IntoResponse {
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

pub async fn post_run(body: String) -> impl IntoResponse {
    let run: Submission = serde_json::from_str(&body).unwrap();
    // debug!("Run: {:?}", run);
    let res = run.run();
    (StatusCode::OK, serde_json::to_string(&res).unwrap())
}