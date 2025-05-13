use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use lettre::{
    message::header::ContentType, transport::smtp::authentication::Credentials, Message,
    SmtpTransport, Transport,
};
use rand::{distr::Alphanumeric, Rng};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::MySqlPool;

use crate::{
    crypt, db, handlers::{ErrorResponse, ErrorTypes}
};

#[derive(Serialize, Deserialize)]
pub struct ValidateTokenBody {
    token: String,
}

pub async fn validate_reset(
    State(pool): State<MySqlPool>,
    Query(token_data): Query<ValidateTokenBody>,
) -> Result<Response, Response> {
    match db::reset_tokens::validate_token(&pool, token_data.token).await {
        Ok(_) => return Ok((StatusCode::OK).into_response()),
        Err(why) => {
            eprintln!("{}", why);
            return Err((
                StatusCode::FORBIDDEN,
                axum::Json(ErrorResponse::new(
                    ErrorTypes::InvalidResetToken,
                    "Reset token is no longer valid",
                )),
            )
                .into_response());
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct CreateResetBody {
    email: String,
}

pub async fn create_reset(
    State(pool): State<MySqlPool>,
    Json(data): Json<CreateResetBody>,
) -> anyhow::Result<Response, Response> {
    if let Err(why) = db::users::email_exists(&pool, &data.email).await {
        eprintln!("Such user does not exist: {}", why);
        return Err((
            StatusCode::NOT_FOUND,
            axum::Json(ErrorResponse::new(
                ErrorTypes::UserNotExists,
                "Such email does not exist",
            )),
        )
            .into_response());
    }

    let s: String = rand::rng()
        .sample_iter(&Alphanumeric)
        .take(16)
        .map(char::from)
        .collect();
    let mut hasher = Sha256::new();
    hasher.update(s.as_bytes());
    let result = hasher.finalize();
    let token = hex::encode(result);

    match db::reset_tokens::insert_token(&pool, &data.email, &token).await {
        Ok(_) => {
            let email = Message::builder()
                .from("TeoNeo <d4nikla@yandex.ru>".parse().unwrap())
                .to(format!("Client <{}>", data.email).parse().unwrap())
                .subject("Password Reset")
                .header(ContentType::TEXT_PLAIN)
                .body(format!("You have recently requested a password reset:\nLink: http://5.129.200.137/reset/token?={}", token))
                .unwrap();

            let creds = Credentials::new(
                "d4nikla@yandex.ru".to_owned(),
                "ijjwqgxtuyodnihr".to_owned(),
            );

            let mailer = SmtpTransport::relay("smtp.yandex.ru")
                .unwrap()
                .port(465) // или 465
                .credentials(creds)
                .build();

            // Send the email
            match mailer.send(&email) {
                Ok(_) => println!("Email sent successfully!"),
                Err(e) => eprintln!("Could not send email: {e:?}"),
            }
            return Ok((StatusCode::OK).into_response());
        }
        Err(why) => {
            eprintln!("Inserting rtoken: {}", why);
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                axum::Json(ErrorResponse::new(
                    ErrorTypes::InternalError,
                    "Could not insert a new token",
                )),
            )
                .into_response());
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct ResetPasswordBody {
    token: String,
    password: String,
}

pub async fn reset_password(State(pool): State<MySqlPool>, Json(data) : Json<ResetPasswordBody>) -> anyhow::Result<Response, Response> {
    match db::reset_tokens::validate_token(&pool, data.token).await {
        Ok(email) => {
            let hashed_password = crypt::password::hash_password(&data.password);
            db::users::set_password_by_email(&pool, &email, &hashed_password).await.unwrap();  
            return Ok((StatusCode::OK).into_response())
        },
        Err(why) => {
            eprintln!("{}", why);
            return Err((
                StatusCode::FORBIDDEN,
                axum::Json(ErrorResponse::new(
                    ErrorTypes::InvalidResetToken,
                    "Reset token is no longer valid",
                )),
            )
                .into_response());
        }
    }
}