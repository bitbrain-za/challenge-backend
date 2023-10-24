use envcrypt::option_envc;

#[derive(Debug, Clone)]
pub struct Config {
    pub db_password: String,
    pub db_url: String,
    pub jwt_secret: String,
    pub jwt_expires_in: String,
    pub jwt_maxage: i32,
}

impl Config {
    pub fn init() -> Config {
        let db_password = option_envc!("DB_PASSWORD").unwrap().to_string();
        let db_url = option_envc!("DATABASE_URL").unwrap().to_string();
        let jwt_secret = option_envc!("JWT_SECRET").unwrap().into();
        let jwt_expires_in = option_envc!("JWT_EXPIRED_IN").unwrap().into();
        let jwt_maxage = option_envc!("JWT_MAXAGE").unwrap();

        Config {
            db_password,
            db_url,
            jwt_secret,
            jwt_expires_in,
            jwt_maxage: jwt_maxage.parse::<i32>().unwrap(),
        }
    }
}
