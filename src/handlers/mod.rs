use std::fmt::Display;

use axum::response::IntoResponse;
use reqwest::StatusCode;

use crate::common::error::{ErrorResponse, ErrorTypes};

pub mod auth;
pub mod oauth;


pub fn error_response(
    status: StatusCode,
    error_type: ErrorTypes,
    error_msg: &str,
) -> axum::response::Response {
    (
        status,
        axum::Json(ErrorResponse::new(error_type, error_msg)),
    )
        .into_response()
}

#[macro_export]
macro_rules! error_response {
    ($status:expr, $error_type:expr, $($arg:tt)*) => {
        crate::handlers::error_response($status, $error_type, &format!($($arg)*))
    };
}