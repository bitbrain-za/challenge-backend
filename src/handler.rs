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

pub async fn get_challenge(extract::Path(id): extract::Path<String>) -> impl IntoResponse {
    let challenges = format!("challenge for {}", id);
    debug!("Get challenge: {}", challenges);

    let judge = option_env!("JUDGE_PATH").unwrap_or("judge").to_string();
    let mut command = std::process::Command::new(judge);
    command.arg("-g").arg(id);

    let output = match command.output() {
        Ok(o) => {
            debug!("Output: {:?}", o);
            if o.status.success() {
                let s = String::from_utf8_lossy(&o.stdout).to_string();
                let json: serde_json::Value = match serde_json::from_str(&s) {
                    Ok(j) => j,
                    Err(e) => {
                        error!("Failed to parse json: {}", e);
                        return (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "Failed to parse json".to_string(),
                        );
                    }
                };
                let json = match serde_json::to_string_pretty(&json) {
                    Ok(j) => j,
                    Err(e) => {
                        error!("Failed to pretty print json: {}", e);
                        return (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "Failed to pretty print json".to_string(),
                        );
                    }
                };
                debug!("Output: {}", json);
                json
            } else {
                log::error!(
                    "Error running script: {}",
                    String::from_utf8_lossy(&o.stderr)
                );
                String::from_utf8_lossy(&o.stderr).to_string()
            }
        }
        Err(e) => e.to_string(),
    };
    log::debug!("Output: {:?}", output);
    (StatusCode::OK, output)
}

pub async fn get_challenges() -> impl IntoResponse {
    let challenges = String::from("Get all challenges");
    debug!("Get challenge: {}", challenges);

    let judge = option_env!("JUDGE_PATH").unwrap_or("judge").to_string();
    let mut command = std::process::Command::new(judge);
    command.arg("-g");

    let output = match command.output() {
        Ok(o) => {
            if o.status.success() {
                let s = String::from_utf8_lossy(&o.stdout).to_string();
                let json: serde_json::Value = match serde_json::from_str(&s) {
                    Ok(j) => j,
                    Err(e) => {
                        error!("Failed to parse json: {}", e);
                        return (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "Failed to parse json".to_string(),
                        );
                    }
                };
                match serde_json::to_string(&json) {
                    Ok(j) => j,
                    Err(e) => {
                        error!("Failed to pretty print json: {}", e);
                        return (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "Failed to pretty print json".to_string(),
                        );
                    }
                }
            } else {
                log::error!(
                    "Error running script: {}",
                    String::from_utf8_lossy(&o.stderr)
                );
                String::from_utf8_lossy(&o.stderr).to_string()
            }
        }
        Err(e) => e.to_string(),
    };
    log::debug!("Output: {:?}", output);
    (StatusCode::OK, output)
}
