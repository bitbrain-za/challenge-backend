use envcrypt::option_envc;

#[derive(Debug, Clone)]
pub struct Config {
    pub db_password: String,
    pub db_url: String,
    pub redis_url: String,
    pub client_origin: String,
    pub my_url: String,
    pub my_ip: String,

    pub access_token_private_key: String,
    pub access_token_public_key: String,
    pub access_token_expires_in: String,
    pub access_token_max_age: i64,

    pub refresh_token_private_key: String,
    pub refresh_token_public_key: String,
    pub refresh_token_expires_in: String,
    pub refresh_token_max_age: i64,
    // pub tls_cert_path: String,
    // pub tls_key_path: String,
}

impl Config {
    pub fn init() -> Config {
        let db_password = option_envc!("DB_PASSWORD").unwrap().to_string();
        let db_url = option_envc!("DATABASE_URL").unwrap().to_string();
        let my_url = option_envc!("MY_URL").unwrap().to_string();
        let my_ip = option_envc!("MY_IP").unwrap().to_string();

        let client_origin = option_envc!("CLIENT_ORIGIN").unwrap().into();
        let redis_url = option_envc!("REDIS_URL").unwrap().into();

        let access_token_private_key = option_envc!("ACCESS_TOKEN_PRIVATE_KEY").unwrap().into();
        let access_token_public_key = option_envc!("ACCESS_TOKEN_PUBLIC_KEY").unwrap().into();
        let access_token_expires_in = option_envc!("ACCESS_TOKEN_EXPIRES_IN").unwrap().into();
        let access_token_max_age = option_envc!("ACCESS_TOKEN_MAXAGE")
            .unwrap()
            .parse::<i64>()
            .unwrap();

        let refresh_token_private_key = option_envc!("REFRESH_TOKEN_PRIVATE_KEY").unwrap().into();
        let refresh_token_public_key = option_envc!("REFRESH_TOKEN_PUBLIC_KEY").unwrap().into();
        let refresh_token_expires_in = option_envc!("REFRESH_TOKEN_EXPIRES_IN").unwrap().into();
        let refresh_token_max_age = option_envc!("REFRESH_TOKEN_MAXAGE")
            .unwrap()
            .parse::<i64>()
            .unwrap();

        // let tls_cert_path = option_envc!("TLS_CERT_PATH").unwrap().into();
        // let tls_key_path = option_envc!("TLS_KEY_PATH").unwrap().into();

        Config {
            my_url,
            client_origin,
            db_password,
            db_url,
            redis_url,
            my_ip,

            access_token_private_key,
            access_token_public_key,
            access_token_expires_in,
            access_token_max_age,

            refresh_token_private_key,
            refresh_token_public_key,
            refresh_token_expires_in,
            refresh_token_max_age,
            // tls_cert_path,
            // tls_key_path,
        }
    }
}
