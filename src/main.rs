mod config;
mod email;
mod handler;
mod jwt_auth;
mod login_handler;
mod route;
mod run;
mod token;
mod user;
use axum::http::{
    header::{AUTHORIZATION, CONTENT_TYPE, ORIGIN},
    Method,
};
// use axum_server::tls_rustls::RustlsConfig;
use config::Config;
use envcrypt::option_envc;
use log::{info, LevelFilter};
use redis::Client;
use route::create_router;
use simple_logger::SimpleLogger;
use sqlx::{mysql::MySqlPoolOptions, MySql, Pool};
use std::net::SocketAddr;
// use std::path::PathBuf;
use std::sync::Arc;
use tower_http::cors::CorsLayer;

pub struct AppState {
    env: Config,
    db: Pool<MySql>,
    redis_client: Client,
}

#[derive(Clone, Copy)]
struct Ports {
    http: u16,
    https: u16,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut ports = Ports {
        https: 3000,
        http: 3000,
    };

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
    // let mut tls = false;
    for (i, arg) in args.iter().enumerate() {
        // if arg == "-S" {
        //     tls = true;
        // }
        if arg == "-p" {
            if let Some(p) = args.get(i + 1) {
                let p = p.parse::<u16>().expect("Invalid port number");
                info!("Using port {}", p);
                ports.https = p;
                ports.http = p;
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

    // let tls_config = RustlsConfig::from_pem_file(
    //     PathBuf::from(&config.tls_cert_path),
    //     PathBuf::from(&config.tls_key_path),
    // )
    // .await
    // .unwrap();

    let origins = [
        "http://localhost:8080".parse()?,
        config.client_origin.as_str().parse()?,
    ];
    let cors = CorsLayer::new()
        .allow_methods([Method::GET, Method::POST])
        .allow_headers([AUTHORIZATION, CONTENT_TYPE, ORIGIN])
        .allow_credentials(true)
        .allow_origin(origins);

    let app = create_router(Arc::new(AppState {
        db: pool.clone(),
        env: config.clone(),
        redis_client: redis_client.clone(),
    }))
    .layer(cors);

    // if tls {
    //     info!("Starting server with TLS on port {}", ports.https);
    //     let addr = SocketAddr::from(([0, 0, 0, 0], ports.https));
    //     axum_server::bind_rustls(addr, tls_config)
    //         .serve(app.into_make_service())
    //         .await
    //         .unwrap();
    // } else {
    info!("Starting server on port {}", ports.http);
    let addr = SocketAddr::from(([0, 0, 0, 0], ports.http));
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
    // }
    Ok(())
}
