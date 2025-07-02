use std::any::Any;

use axum::response::{IntoResponse, Response};
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

pub struct AppError(anyhow::Error);
impl IntoResponse for AppError {
    fn into_response(self) -> axum::response::Response {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            axum::Json(ErrorResponse::new(
                ErrorTypes::InternalError,
                &format!("Something went wrong: {}", self.0),
            )),
        )
            .into_response()
    }
}

impl<E: Into<anyhow::Error>> From<E> for AppError {
    fn from(value: E) -> Self {
        Self(value.into())
    }
}

// Errors stuff
#[derive(Serialize, Deserialize, ToSchema)]
pub struct ErrorResponse {
    pub error_type: String,
    pub error_msg: String,
}

impl ErrorResponse {
    pub fn new(error_type: ErrorTypes, error_msg: &str) -> Self {
        Self {
            error_type: error_type.as_str().to_string(),
            error_msg: error_msg.to_owned(),
        }
    }
}

#[derive(Debug)]
pub enum ErrorTypes {
    InternalError,
    JwtTokenExpired,
    BadData,
    UserNotExists,
    NotEnoughPermissions,
    InvalidResetToken,
    UserAlreadyExists,
    RefreshTokenExpired,
    CookieMissing,
    NoAuthHeader
}

impl ErrorTypes {
    pub fn as_str(&self) -> &'static str {
        match self {
            ErrorTypes::InternalError => "internal_error",
            ErrorTypes::JwtTokenExpired => "jwt_token_expired",
            ErrorTypes::UserNotExists => "user_not_exists",
            ErrorTypes::NotEnoughPermissions => "not_enough_permissions",
            ErrorTypes::BadData => "bad_data",
            ErrorTypes::InvalidResetToken => "invalid_reset_token",
            ErrorTypes::UserAlreadyExists => "user_already_exists",
            ErrorTypes::RefreshTokenExpired => "refresh_token_expired",
            ErrorTypes::CookieMissing => "cookie_missing",
            ErrorTypes::NoAuthHeader => "no_auth_header"
        }
    }
}

pub fn internal_server_error_handler(err: Box<dyn Any + Send + 'static>) -> Response {
    let details = if let Some(s) = err.downcast_ref::<String>() {
        s.clone()
    } else if let Some(s) = err.downcast_ref::<&str>() {
        s.to_string()
    } else {
        "Unknown panic message".to_string()
    };
    println!("Internal server error catched: {}", details);
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        axum::Json(ErrorResponse::new(ErrorTypes::InternalError, &details)), // Should not panic, because struct is always valid for converting into JSON
    )
        .into_response()
}
