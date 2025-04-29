use std::fmt::Display;

use serde::{Deserialize, Serialize};

// Payloads

#[derive(Serialize)]
pub struct TokensPayload {
    pub jwt_token: String,
    pub refresh_token: String,
}

// Error types
#[derive(Serialize, Deserialize)]
pub enum AuthErrors {
    JwtTokenExpired,
    RefreshTokenExpired,
    BadData,
    UserAlreadyExists,
    UserNotExists,
    InvalidCreds,
}

#[derive(Serialize, Deserialize)]
pub struct AuthError {
    error_type: AuthErrors,
    message: String,
}
impl AuthError {
    pub fn new(error_type: AuthErrors, message: &str) -> Self {
        Self {
            error_type,
            message: message.to_string(),
        }
    }
}

impl Display for AuthErrors {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::JwtTokenExpired => write!(f, "jwt_token_expired"),
            Self::RefreshTokenExpired => write!(f, "refresh_token_expired"),
            Self::BadData => write!(f, "bad_data"),
            Self::UserAlreadyExists => write!(f, "user_already_exists"),
            Self::UserNotExists => write!(f, "user_not_exists"),
            Self::InvalidCreds => write!(f, "invalid_creds"),
        }
    }
}
