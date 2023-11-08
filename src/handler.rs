use super::jwt_auth::JWTAuthMiddleware;
use crate::run::{Submission, SubmissionBuilder};
use axum::{
    extract::{self, Multipart},
    http::StatusCode,
    response::IntoResponse,
    Extension,
};
use envcrypt::option_envc;
use log::{debug, error};
use scoreboard_db::{Db, Score};

pub async fn get_scores(extract::Path(id): extract::Path<String>) -> impl IntoResponse {
    const MAX_SCORES: Option<usize> = Some(1000);
    debug!("get Scores");
    let db_pass = match option_envc!("DB_PASSWORD") {
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

pub async fn post_run(state: Extension<JWTAuthMiddleware>, body: String) -> impl IntoResponse {
    debug!("Submission from {}", state.user.name);
    let mut run: Submission = match serde_json::from_str(&body) {
        Ok(r) => r,
        Err(e) => {
            error!("Failed to parse submission: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to parse submission".to_string(),
            );
        }
    };
    run.sanitise();

    debug!("Submission: {:?}", run);
    run.player = state.user.name.clone();
    let res = run.run();
    (StatusCode::OK, serde_json::to_string(&res).unwrap())
}

pub async fn post_binary(
    state: Extension<JWTAuthMiddleware>,
    mut multipart: Multipart,
) -> impl IntoResponse {
    let mut builder = SubmissionBuilder::new();

    debug!("Submission from {}", state.user.name);
    builder = builder.player(&state.user.name);
    while let Some(field) = multipart.next_field().await.unwrap() {
        let name = field.name().unwrap().to_string();

        if name == "binary" {
            let data = field.bytes().await.unwrap();
            // debug!("Binary data: {:?}", data);
            builder = builder.binary(data.to_vec());
            continue;
        }

        let data = field.bytes().await.unwrap();
        builder = match builder.set_field(&name, &String::from_utf8(data.to_vec()).unwrap()) {
            Ok(b) => b,
            Err(e) => {
                error!("Failed to set field: {}", e);
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Failed to set field".to_string(),
                );
            }
        };
    }

    builder = builder.player(&state.user.name);
    let submission = match builder.build() {
        Ok(s) => s,
        Err(e) => {
            error!("Failed to build submission: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to build submission".to_string(),
            );
        }
    };

    let res = submission.run();

    (StatusCode::OK, serde_json::to_string(&res).unwrap())
}
