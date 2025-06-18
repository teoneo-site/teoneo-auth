use std::fmt::Display;

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

pub mod login;
pub mod password;
pub mod register;
pub mod token;
pub mod types;
pub mod oauth;

// Errors stuff
#[derive(Serialize, Deserialize, ToSchema)]
pub struct ErrorResponse {
    error_type: String,
    error_msg: String,
}

impl ErrorResponse {
    pub fn new(error_type: ErrorTypes, error_msg: &str) -> Self {
        Self {
            error_type: error_type.to_string(),
            error_msg: error_msg.to_owned(),
        }
    }
}

// pub trait IntoErrorResponse {
//     fn into_error_response(&self) -> ErrorResponse;
// }

pub enum ErrorTypes {
    InternalError,
    JwtTokenExpired,
    MaxAttemptsSubmit,
    BadData,
    UserNotExists,
    UserAlreadyExists,
    RefreshTokenExpired,
    InvalidResetToken,
    CookieMissing,
}

impl Display for ErrorTypes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InternalError => write!(f, "server_internal_error"),
            Self::JwtTokenExpired => write!(f, "jwt_token_expired"),
            Self::MaxAttemptsSubmit => write!(f, "max_attempts_submit"),
            Self::BadData => write!(f, "bad_data"),
            Self::UserNotExists => write!(f, "user_not_exists"),
            Self::UserAlreadyExists => write!(f, "user_alread_exists"),
            Self::RefreshTokenExpired => write!(f, "refresh_token_expired"),
            Self::InvalidResetToken => write!(f, "invalid_reset_token"),
            Self::CookieMissing => write!(f, "cookie_missing")
        }
    }
}
