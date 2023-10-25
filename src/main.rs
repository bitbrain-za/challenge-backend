mod config;
mod handler;
mod jwt_auth;
mod login_handler;
mod route;
mod run;
mod token;
mod user;
use axum::http::{
    header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE, ORIGIN},
    HeaderValue, Method,
};
use config::Config;
use envcrypt::option_envc;
use log::{info, LevelFilter};
use redis::Client;
use route::create_router;
use simple_logger::SimpleLogger;
use sqlx::{mysql::MySqlPoolOptions, MySql, Pool};
use std::sync::Arc;
use tower_http::cors::CorsLayer;

pub struct AppState {
    env: Config,
    db: Pool<MySql>,
    redis_client: Client,
}

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

    let config = Config::init();

    let pool = MySqlPoolOptions::new()
        .max_connections(5)
        .connect(config.db_url.as_str())
        .await
        .expect("Failed to connect to the DB");

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

    let redis_client = match Client::open(config.redis_url.to_owned()) {
        Ok(client) => {
            println!("✅Connection to the redis is successful!");
            client
        }
        Err(e) => {
            println!("🔥 Error connecting to Redis: {}", e);
            std::process::exit(1);
        }
    };

    let url = format!("0.0.0.0:{}", port);
    let cors = CorsLayer::new()
        .allow_methods([Method::GET, Method::POST, Method::PATCH, Method::DELETE])
        //TODO review this
        .allow_credentials(true)
        .allow_origin(url.parse::<HeaderValue>().unwrap())
        .allow_headers([AUTHORIZATION, ACCEPT, CONTENT_TYPE, ORIGIN]);

    let app = create_router(Arc::new(AppState {
        db: pool.clone(),
        env: config.clone(),
        redis_client: redis_client.clone(),
    }))
    .layer(cors);

    info!("Starting server");
    axum::Server::bind(&url.parse().unwrap())
        .serve(app.into_make_service())
        .await
        .unwrap();

    Ok(())
}
