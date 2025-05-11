use std::fmt::Display;

use axum::{
    http::{header::CONTENT_TYPE, HeaderMap, HeaderValue, StatusCode},
    response::IntoResponse,
};
use serde::{Deserialize, Serialize};

pub mod login;
pub mod register;
pub mod token;
pub mod types;

// Errors stuff
#[derive(Serialize, Deserialize)]
pub struct ErrorResponse {
    error_type: String,
    error_msg: String,
}

pub struct ResponseBody<T: Serialize> {
    pub status: StatusCode,
    pub headers: Option<HeaderMap>,
    pub body: T,
}
impl<T: Serialize> IntoResponse for ResponseBody<T> {
    fn into_response(self) -> axum::response::Response {
        let headers: HeaderMap = self.headers.unwrap_or_else(|| {
            let mut headers = HeaderMap::new();
            headers.append(CONTENT_TYPE, HeaderValue::from_static("application/json"));
            headers
        });

        (self.status, headers, axum::Json(self.body)).into_response()
    }
}
impl<T: Serialize> ResponseBody<T> {
    pub fn new(status: StatusCode, headers: Option<HeaderMap>, body: T) -> Self {
        Self {
            status,
            headers,
            body,
        }
    }
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
        }
    }
}
