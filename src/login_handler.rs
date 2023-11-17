use rand::{distributions::Alphanumeric, rngs::OsRng, Rng};
use std::sync::Arc;

use argon2::{password_hash::SaltString, Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use axum::{
    extract::{Path, State},
    http::{header, HeaderMap, Response, StatusCode},
    response::IntoResponse,
    Extension, Json,
};
use axum_extra::extract::{
    cookie::{Cookie, SameSite},
    CookieJar,
};
use serde_json::json;

use crate::{
    email::Email,
    jwt_auth::JWTAuthMiddleware,
    token::{self, TokenDetails},
    user::{ForgotPasswordSchema, LoginUserSchema, RegisterUserSchema, ResetPasswordSchema, User},
    AppState,
};

use redis::AsyncCommands;

pub async fn register_user_handler(
    State(data): State<Arc<AppState>>,
    Json(body): Json<RegisterUserSchema>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let user_exists: Option<bool> =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM users WHERE email = ?)")
            .bind(body.email.to_owned().to_ascii_lowercase())
            .fetch_one(&data.db)
            .await
            .map_err(|e| {
                let error_response = serde_json::json!({
                    "status": "fail",
                    "message": format!("Database error: {}", e),
                });
                (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response))
            })?;

    if let Some(exists) = user_exists {
        if exists {
            let error_response = serde_json::json!({
                "status": "fail",
                "message": "User with that email already exists",
            });
            return Err((StatusCode::CONFLICT, Json(error_response)));
        }
    }

    if !cfg!(debug_assertions)
        && !body
            .email
            .to_owned()
            .to_ascii_lowercase()
            .contains(option_env!("ALLOWED_DOMAIN").unwrap_or("dummy.com"))
    {
        let error_response = serde_json::json!({
            "status": "fail",
            "message": "Email domain not allowed",
        });
        return Err((StatusCode::FORBIDDEN, Json(error_response)));
    }

    let salt = SaltString::generate(&mut OsRng);
    let hashed_password = Argon2::default()
        .hash_password(body.password.as_bytes(), &salt)
        .map_err(|e| {
            let error_response = serde_json::json!({
                "status": "fail",
                "message": format!("Error while hashing password: {}", e),
            });
            (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response))
        })
        .map(|hash| hash.to_string())?;

    let verification_code = generate_random_string(20);
    let verification_url = format!(
        "{}api/auth/verifyemail/{}",
        data.env.my_url.to_owned(),
        verification_code
    );

    if !cfg!(debug_assertions) {
        let verification_mail = Email::new_registration(
            body.name.to_string(),
            body.email.to_string().to_ascii_lowercase(),
            verification_url,
        );
        verification_mail.send().map_err(|e| {
            let error_response = serde_json::json!({
                "status": "fail",
                "message": format!("Error sending verification email: {}", e),
            });
            (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response))
        })?;

        sqlx::query!(
            "INSERT INTO users (name, email, password, verification_code) VALUES (?, ?, ?, ?)",
            body.name.to_string(),
            body.email.to_string().to_ascii_lowercase(),
            hashed_password,
            verification_code
        )
        .execute(&data.db)
        .await
        .map_err(|e| {
            let error_response = serde_json::json!({
                "status": "fail",
                "message": format!("Database error: {}", e),
            });
            (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response))
        })?;
    } else {
        sqlx::query!(
            "INSERT INTO users (name, email, password, verified) VALUES (?, ?, ?, ?)",
            body.name.to_string(),
            body.email.to_string().to_ascii_lowercase(),
            hashed_password,
            true
        )
        .execute(&data.db)
        .await
        .map_err(|e| {
            let error_response = serde_json::json!({
                "status": "fail",
                "message": format!("Database error: {}", e),
            });
            (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response))
        })?;
    }

    let user_response =
        serde_json::json!({"status": "success","message": "User created successfully"});

    Ok(Json(user_response))
}

pub async fn login_user_handler(
    State(data): State<Arc<AppState>>,
    Json(body): Json<LoginUserSchema>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let user = sqlx::query_as!(
        User,
        "SELECT * FROM users WHERE email = ?",
        body.email.to_ascii_lowercase()
    )
    .fetch_optional(&data.db)
    .await
    .map_err(|e| {
        let error_response = serde_json::json!({
            "Failure":  {
                "status": "error",
                "message": format!("Database error: {}", e)
            }
        });
        (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response))
    })?
    .ok_or_else(|| {
        let error_response = serde_json::json!({
            "Failure": {
                "status": "fail",
                "message": "Invalid email or password"
            }
        });
        (StatusCode::BAD_REQUEST, Json(error_response))
    })?;

    let is_valid = match PasswordHash::new(&user.password) {
        Ok(parsed_hash) => Argon2::default()
            .verify_password(body.password.as_bytes(), &parsed_hash)
            .map_or(false, |_| true),
        Err(_) => false,
    };

    if !is_valid {
        let error_response = serde_json::json!({
            "Failure": {
                "status": "fail",
                "message": "Invalid email or password"
            }
        });
        return Err((StatusCode::BAD_REQUEST, Json(error_response)));
    }

    let access_token_details = generate_token(
        user.id,
        data.env.access_token_max_age,
        data.env.access_token_private_key.to_owned(),
    )?;
    let refresh_token_details = generate_token(
        user.id,
        data.env.refresh_token_max_age,
        data.env.refresh_token_private_key.to_owned(),
    )?;

    save_token_data_to_redis(&data, &access_token_details, data.env.access_token_max_age).await?;
    save_token_data_to_redis(
        &data,
        &refresh_token_details,
        data.env.refresh_token_max_age,
    )
    .await?;

    let access_cookie = Cookie::build(
        "access_token",
        access_token_details.token.clone().unwrap_or_default(),
    )
    .path("/")
    .max_age(time::Duration::minutes(data.env.access_token_max_age * 60))
    .same_site(SameSite::Strict)
    // .secure(true)
    .http_only(true)
    .finish();
    let refresh_cookie = Cookie::build(
        "refresh_token",
        refresh_token_details.token.unwrap_or_default(),
    )
    .path("/")
    .max_age(time::Duration::minutes(data.env.refresh_token_max_age * 60))
    .same_site(SameSite::Strict)
    .http_only(true)
    // .secure(true)
    .finish();

    let logged_in_cookie = Cookie::build("logged_in", "true")
        .path("/")
        // .secure(true)
        .same_site(SameSite::Strict)
        .http_only(true)
        .finish();

    let mut response = Response::new(
        json!({
            "Success": {
                "status": "success",
                "access_token": access_token_details.token.unwrap()
            }
        })
        .to_string(),
    );
    let mut headers = HeaderMap::new();
    headers.append(
        header::SET_COOKIE,
        access_cookie.to_string().parse().unwrap(),
    );
    headers.append(
        header::SET_COOKIE,
        refresh_cookie.to_string().parse().unwrap(),
    );
    headers.append(
        header::SET_COOKIE,
        logged_in_cookie.to_string().parse().unwrap(),
    );

    response.headers_mut().extend(headers);
    Ok(response)
}

pub async fn refresh_access_token_handler(
    cookie_jar: CookieJar,
    State(data): State<Arc<AppState>>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let message = "could not refresh access token";

    let refresh_token = cookie_jar
        .get("refresh_token")
        .map(|cookie| cookie.value().to_string())
        .ok_or_else(|| {
            let error_response = serde_json::json!({
                "status": "fail",
                "message": message
            });
            (StatusCode::FORBIDDEN, Json(error_response))
        })?;

    let refresh_token_details =
        match token::verify_jwt_token(data.env.refresh_token_public_key.to_owned(), &refresh_token)
        {
            Ok(token_details) => token_details,
            Err(e) => {
                let error_response = serde_json::json!({
                    "status": "fail",
                    "message": format_args!("{:?}", e)
                });
                return Err((StatusCode::UNAUTHORIZED, Json(error_response)));
            }
        };

    let mut redis_client = data
        .redis_client
        .get_async_connection()
        .await
        .map_err(|e| {
            let error_response = serde_json::json!({
                "status": "error",
                "message": format!("Redis error: {}", e),
            });
            (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response))
        })?;

    let redis_token_user_id = redis_client
        .get::<_, String>(refresh_token_details.token_uuid.to_string())
        .await
        .map_err(|_| {
            let error_response = serde_json::json!({
                "status": "error",
                "message": "Token is invalid or session has expired",
            });
            (StatusCode::UNAUTHORIZED, Json(error_response))
        })?;

    let user_id = &redis_token_user_id.parse::<i64>().map_err(|_| {
        let error_response = serde_json::json!({
            "status": "error",
            "message": "Token is invalid or session has expired",
        });
        (StatusCode::UNAUTHORIZED, Json(error_response))
    })?;

    let user = sqlx::query_as!(User, "SELECT * FROM users WHERE id = ?", user_id)
        .fetch_optional(&data.db)
        .await
        .map_err(|e| {
            let error_response = serde_json::json!({
                "status": "fail",
                "message": format!("Error fetching user from database: {}", e),
            });
            (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response))
        })?;

    let user = user.ok_or_else(|| {
        let error_response = serde_json::json!({
            "status": "fail",
            "message": "The user belonging to this token no longer exists".to_string(),
        });
        (StatusCode::UNAUTHORIZED, Json(error_response))
    })?;

    let access_token_details = generate_token(
        user.id,
        data.env.access_token_max_age,
        data.env.access_token_private_key.to_owned(),
    )?;

    save_token_data_to_redis(&data, &access_token_details, data.env.access_token_max_age).await?;

    let access_cookie = Cookie::build(
        "access_token",
        access_token_details.token.clone().unwrap_or_default(),
    )
    .path("/")
    .max_age(time::Duration::minutes(data.env.access_token_max_age * 60))
    .same_site(SameSite::Lax)
    .http_only(true)
    .finish();

    let logged_in_cookie = Cookie::build("logged_in", "true")
        .path("/")
        .max_age(time::Duration::minutes(data.env.access_token_max_age * 60))
        .same_site(SameSite::Lax)
        .http_only(false)
        .finish();

    let mut response = Response::new(
        json!({"status": "success", "message": access_token_details.token.unwrap()}).to_string(),
    );
    let mut headers = HeaderMap::new();
    headers.append(
        header::SET_COOKIE,
        access_cookie.to_string().parse().unwrap(),
    );
    headers.append(
        header::SET_COOKIE,
        logged_in_cookie.to_string().parse().unwrap(),
    );

    response.headers_mut().extend(headers);
    Ok(response)
}

pub async fn logout_handler(
    cookie_jar: CookieJar,
    Extension(auth_guard): Extension<JWTAuthMiddleware>,
    State(data): State<Arc<AppState>>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let message = "Token is invalid or session has expired";

    let refresh_token = cookie_jar
        .get("refresh_token")
        .map(|cookie| cookie.value().to_string())
        .ok_or_else(|| {
            let error_response = serde_json::json!({
                "status": "fail",
                "message": message
            });
            (StatusCode::FORBIDDEN, Json(error_response))
        })?;

    let refresh_token_details =
        match token::verify_jwt_token(data.env.refresh_token_public_key.to_owned(), &refresh_token)
        {
            Ok(token_details) => token_details,
            Err(e) => {
                let error_response = serde_json::json!({
                    "status": "fail",
                    "message": format_args!("{:?}", e)
                });
                return Err((StatusCode::UNAUTHORIZED, Json(error_response)));
            }
        };

    let mut redis_client = data
        .redis_client
        .get_async_connection()
        .await
        .map_err(|e| {
            let error_response = serde_json::json!({
                "status": "error",
                "message": format!("Redis error: {}", e),
            });
            (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response))
        })?;

    redis_client
        .del(&[
            refresh_token_details.token_uuid.to_string(),
            auth_guard.access_token_uuid.to_string(),
        ])
        .await
        .map_err(|e| {
            let error_response = serde_json::json!({
                "status": "error",
                "message": format_args!("{:?}", e)
            });
            (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response))
        })?;

    let access_cookie = Cookie::build("access_token", "")
        .path("/")
        .max_age(time::Duration::minutes(-1))
        .same_site(SameSite::Lax)
        .http_only(true)
        .finish();
    let refresh_cookie = Cookie::build("refresh_token", "")
        .path("/")
        .max_age(time::Duration::minutes(-1))
        .same_site(SameSite::Lax)
        .http_only(true)
        .finish();

    let logged_in_cookie = Cookie::build("logged_in", "true")
        .path("/")
        .max_age(time::Duration::minutes(-1))
        .same_site(SameSite::Lax)
        .http_only(false)
        .finish();

    let mut headers = HeaderMap::new();
    headers.append(
        header::SET_COOKIE,
        access_cookie.to_string().parse().unwrap(),
    );
    headers.append(
        header::SET_COOKIE,
        refresh_cookie.to_string().parse().unwrap(),
    );
    headers.append(
        header::SET_COOKIE,
        logged_in_cookie.to_string().parse().unwrap(),
    );

    let mut response = Response::new(json!({"status": "success"}).to_string());
    response.headers_mut().extend(headers);
    Ok(response)
}

pub async fn delete_account_handler(
    cookie_jar: CookieJar,
    Extension(auth_guard): Extension<JWTAuthMiddleware>,
    State(data): State<Arc<AppState>>,
    Json(body): Json<ForgotPasswordSchema>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let message = "Token is invalid or session has expired";

    let refresh_token = cookie_jar
        .get("refresh_token")
        .map(|cookie| cookie.value().to_string())
        .ok_or_else(|| {
            let error_response = serde_json::json!({
                "status": "fail",
                "message": message
            });
            (StatusCode::FORBIDDEN, Json(error_response))
        })?;

    let refresh_token_details =
        match token::verify_jwt_token(data.env.refresh_token_public_key.to_owned(), &refresh_token)
        {
            Ok(token_details) => token_details,
            Err(e) => {
                let error_response = serde_json::json!({
                    "status": "fail",
                    "message": format_args!("{:?}", e)
                });
                return Err((StatusCode::UNAUTHORIZED, Json(error_response)));
            }
        };

    let mut redis_client = data
        .redis_client
        .get_async_connection()
        .await
        .map_err(|e| {
            let error_response = serde_json::json!({
                "status": "error",
                "message": format!("Redis error: {}", e),
            });
            (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response))
        })?;

    redis_client
        .del(&[
            refresh_token_details.token_uuid.to_string(),
            auth_guard.access_token_uuid.to_string(),
        ])
        .await
        .map_err(|e| {
            let error_response = serde_json::json!({
                "status": "error",
                "message": format_args!("{:?}", e)
            });
            (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response))
        })?;

    let _ = sqlx::query_as!(
        User,
        "DELETE FROM users WHERE email = ?",
        body.email.to_ascii_lowercase()
    )
    .fetch_optional(&data.db)
    .await
    .map_err(|e| {
        let error_response = serde_json::json!({
            "Failure":  {
                "status": "error",
                "message": format!("Database error: {}", e)
            }
        });
        (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response))
    })?;

    let access_cookie = Cookie::build("access_token", "")
        .path("/")
        .max_age(time::Duration::minutes(-1))
        .same_site(SameSite::Lax)
        .http_only(true)
        .finish();
    let refresh_cookie = Cookie::build("refresh_token", "")
        .path("/")
        .max_age(time::Duration::minutes(-1))
        .same_site(SameSite::Lax)
        .http_only(true)
        .finish();

    let logged_in_cookie = Cookie::build("logged_in", "false")
        .path("/")
        .max_age(time::Duration::minutes(-1))
        .same_site(SameSite::Lax)
        .http_only(false)
        .finish();

    let mut headers = HeaderMap::new();
    headers.append(
        header::SET_COOKIE,
        access_cookie.to_string().parse().unwrap(),
    );
    headers.append(
        header::SET_COOKIE,
        refresh_cookie.to_string().parse().unwrap(),
    );
    headers.append(
        header::SET_COOKIE,
        logged_in_cookie.to_string().parse().unwrap(),
    );

    let mut response = Response::new(json!({"status": "success"}).to_string());
    response.headers_mut().extend(headers);
    Ok(response)
}

pub async fn verify_email_handler(
    State(data): State<Arc<AppState>>,
    Path(verification_code): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let user: User = sqlx::query_as("SELECT * FROM users WHERE verification_code = ?")
        .bind(&verification_code)
        .fetch_optional(&data.db)
        .await
        .map_err(|e| {
            let error_response = serde_json::json! ({
                "status": "error",
                "message:": format!("Database error: {}", e),
            });
            (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response))
        })?
        .ok_or_else(|| {
            let error_response = serde_json::json! ({
                "status": "fail",
                "message:": "Invalid verification code or user doesn't exist".to_string(),
            });
            (StatusCode::UNAUTHORIZED, Json(error_response))
        })?;

    if user.verified > 0 {
        let error_response = serde_json::json! ({
            "status": "fail",
            "message:": "User already verified".to_string(),
        });
        return Err((StatusCode::CONFLICT, Json(error_response)));
    }

    sqlx::query("UPDATE users SET verification_code = ?, verified = ? WHERE verification_code = ?")
        .bind(Option::<String>::None)
        .bind(true)
        .bind(&verification_code)
        .execute(&data.db)
        .await
        .map_err(|e| {
            let error_response = serde_json::json! ({
                "status": "fail",
                "message": format!("Error updating user: {}", e),
            });
            (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response))
        })?;

    let response = serde_json::json!({
            "status": "success",
            "message": "Email verified successfully"
        }
    );

    Ok(Json(response))
}

pub async fn forgot_password_handler(
    State(data): State<Arc<AppState>>,
    Json(body): Json<ForgotPasswordSchema>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let err_message = "You will receive a password reset email if user with that email exist";
    let email_address = body.email.to_owned().to_ascii_lowercase();

    let user: User = sqlx::query_as("SELECT * FROM users WHERE email = ?")
        .bind(&email_address.clone())
        .fetch_optional(&data.db)
        .await
        .map_err(|e| {
            let error_response = serde_json::json!( {
                "status": "error",
                "message": format!("Database error: {}", e),
            });
            (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response))
        })?
        .ok_or_else(|| {
            let error_response = serde_json::json!( {
                "status": "fail",
                "message": err_message.to_string(),
            });
            (StatusCode::OK, Json(error_response))
        })?;

    if 0 == user.verified {
        let error_response = serde_json::json!( {
            "status": "fail",
            "message": "Account not verified".to_string(),
        });
        return Err((StatusCode::FORBIDDEN, Json(error_response)));
    }

    let password_reset_token = generate_random_string(20);
    let password_token_expires_in = 10; // 10 minutes
    let password_reset_at =
        chrono::Utc::now() + chrono::Duration::minutes(password_token_expires_in);

    let reset_mail = Email::new_password_reset(
        user.name,
        body.email.to_string().to_ascii_lowercase(),
        &password_reset_token,
    );
    reset_mail.send().map_err(|e| {
        let error_response = serde_json::json!({
            "status": "fail",
            "message": format!("Error sending reset email: {}", e),
        });
        (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response))
    })?;

    sqlx::query("UPDATE users SET password_reset_token = ?, password_reset_at = ? WHERE email = ?")
        .bind(password_reset_token)
        .bind(password_reset_at)
        .bind(&email_address.clone())
        .execute(&data.db)
        .await
        .map_err(|e| {
            let error_response = serde_json::json!( {
                "status": "fail",
                "message": format!("Error updating user: {}", e),
            });
            (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response))
        })?;

    let response = serde_json::json!({
            "status": "success",
            "message": err_message
        }
    );

    Ok(Json(response))
}

pub async fn reset_password_handler(
    State(data): State<Arc<AppState>>,
    Path(password_reset_token): Path<String>,
    Json(body): Json<ResetPasswordSchema>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let user: User = sqlx::query_as(
        "SELECT * FROM users WHERE password_reset_token = ? AND password_reset_at > ?",
    )
    .bind(password_reset_token)
    .bind(chrono::Utc::now())
    .fetch_optional(&data.db)
    .await
    .map_err(|e| {
        let error_response = serde_json::json! ( {
            "status": "error",
            "message": format!("Database error: {}", e),
        });
        (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response))
    })?
    .ok_or_else(|| {
        let error_response = serde_json::json! ( {
            "status": "fail",
            "message": "The password reset token is invalid or has expired".to_string(),
        });
        (StatusCode::FORBIDDEN, Json(error_response))
    })?;

    let salt = SaltString::generate(&mut OsRng);
    let hashed_password = Argon2::default()
        .hash_password(body.password.as_bytes(), &salt)
        .map_err(|e| {
            let error_response = serde_json::json! ( {
                "status": "fail",
                "message": format!("Error while hashing password: {}", e),
            });
            (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response))
        })
        .map(|hash| hash.to_string())?;

    sqlx::query(
        "UPDATE users SET password = ?, password_reset_token = ?, password_reset_at = ? WHERE email = ?",
    )
    .bind(hashed_password)
    .bind(Option::<String>::None)
    .bind(Option::<String>::None)
    .bind(&user.email.clone().to_ascii_lowercase())
    .execute(&data.db)
    .await
    .map_err(|e| {
        let error_response = serde_json::json! ( {
            "status": "fail",
            "message": format!("Error updating user: {}", e),
        });
        (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response))
    })?;

    let cookie = Cookie::build("token", "")
        .path("/")
        .max_age(time::Duration::minutes(-1))
        .same_site(SameSite::Lax)
        .http_only(true)
        .finish();

    let mut response = Response::new(
        json!({"status": "success", "message": "Password data updated successfully"}).to_string(),
    );
    response
        .headers_mut()
        .insert(header::SET_COOKIE, cookie.to_string().parse().unwrap());
    Ok(response)
}

fn generate_token(
    user_id: i64,
    max_age: i64,
    private_key: String,
) -> Result<TokenDetails, (StatusCode, Json<serde_json::Value>)> {
    token::generate_jwt_token(user_id, max_age, private_key).map_err(|e| {
        let error_response = serde_json::json!({
            "status": "error",
            "message": format!("error generating token: {}", e),
        });
        (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response))
    })
}

async fn save_token_data_to_redis(
    data: &Arc<AppState>,
    token_details: &TokenDetails,
    max_age: i64,
) -> Result<(), (StatusCode, Json<serde_json::Value>)> {
    let mut redis_client = data
        .redis_client
        .get_async_connection()
        .await
        .map_err(|e| {
            let error_response = serde_json::json!({
                "status": "error",
                "message": format!("Redis error: {}", e),
            });
            (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response))
        })?;
    redis_client
        .set_ex(
            token_details.token_uuid.to_string(),
            token_details.user_id.to_string(),
            (max_age * 60) as usize,
        )
        .await
        .map_err(|e| {
            let error_response = serde_json::json!({
                "status": "error",
                "message": format_args!("{}", e),
            });
            (StatusCode::UNPROCESSABLE_ENTITY, Json(error_response))
        })?;
    Ok(())
}

fn generate_random_string(length: usize) -> String {
    let rng = rand::thread_rng();
    let random_string: String = rng
        .sample_iter(&Alphanumeric)
        .take(length)
        .map(char::from)
        .collect();

    random_string
}

pub async fn cookie_test_handler(
    State(data): State<Arc<AppState>>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let logged_in_cookie = Cookie::build("logged_in", "false")
        .path("/")
        .domain(data.env.my_ip.clone())
        .secure(true)
        .same_site(SameSite::Strict)
        .http_only(true)
        .finish();
    let test_cookie = Cookie::build("foo", "bar")
        .domain(data.env.my_url.clone())
        .path("/app")
        .secure(true)
        .same_site(SameSite::Lax)
        .http_only(true)
        .finish();
    let test_cookie2 = Cookie::build("bar", "bar")
        .path("/")
        .domain(data.env.my_url.clone())
        .secure(true)
        .same_site(SameSite::None)
        .http_only(true)
        .finish();
    let mut response = Response::new(
        json!({
            "Success": {
                "status": "success",
                "access_token": "null"
            }
        })
        .to_string(),
    );
    let mut headers = HeaderMap::new();
    headers.append(header::SET_COOKIE, test_cookie.to_string().parse().unwrap());
    headers.append(
        header::SET_COOKIE,
        test_cookie2.to_string().parse().unwrap(),
    );
    headers.append(
        header::SET_COOKIE,
        logged_in_cookie.to_string().parse().unwrap(),
    );

    response.headers_mut().extend(headers);
    Ok(response)
}
