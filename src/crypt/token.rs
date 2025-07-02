use axum::{
    extract::FromRequestParts,
    response::{IntoResponse, Response},
};
use chrono::{Duration, Utc};
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation, decode};
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};

use crate::common::error::{ErrorResponse, ErrorTypes};

#[derive(Serialize, Deserialize)]
pub struct Claims {
    pub id: u32,
    pub exp: i64,
}

impl<S: std::marker::Sync> FromRequestParts<S> for Claims {
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _: &S,
    ) -> Result<Self, Self::Rejection> {
        let token = parts
            .headers
            .get("Authorization")
            .and_then(|value| value.to_str().ok())
            .and_then(|s| s.split_whitespace().last())
            .ok_or("Missing header")
            .map_err(|why| {
                eprintln!("{}", why);
                (
                    StatusCode::BAD_REQUEST,
                    axum::Json(ErrorResponse::new(
                        ErrorTypes::InternalError,
                        "No auth header",
                    )),
                )
                    .into_response()
            })?;

        Ok(decode::<Claims>(
            token,
            &DecodingKey::from_secret(std::env::var("SECRET_WORD_JWT").unwrap().as_ref()),
            &Validation::default(),
        )
        .map_err(|err| {
            eprintln!("Could not validate: {}", err);
            (
                StatusCode::UNAUTHORIZED,
                axum::Json(ErrorResponse::new(
                    ErrorTypes::JwtTokenExpired,
                    "Token update requested",
                )),
            )
                .into_response()
        })?
        .claims)
    }
}

pub fn make_jwt_token(user_id: u32) -> String {
    let claims = Claims {
        id: user_id,
        exp: (Utc::now() + Duration::hours(4)).timestamp(),
    };
    jsonwebtoken::encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(std::env::var("SECRET_WORD_JWT").unwrap().as_ref()),
    )
    .unwrap()
}

pub fn make_refresh_token(user_id: u32) -> String {
    let claims = Claims {
        id: user_id,
        exp: (Utc::now() + Duration::days(7)).timestamp(),
    };
    jsonwebtoken::encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(std::env::var("SECRET_WORD_REFRESH").unwrap().as_ref()),
    )
    .unwrap()
}

pub fn verify_refresh_token(token: &str) -> anyhow::Result<u32> {
    let validation = Validation::default();

    let claims = decode::<Claims>(
        token,
        &DecodingKey::from_secret(std::env::var("SECRET_WORD_REFRESH").unwrap().as_ref()),
        &validation,
    )?;
    Ok(claims.claims.id)
}

pub fn verify_jwt_token(token: &str) -> anyhow::Result<u32> {
    let validation = Validation::default();

    let claims = decode::<Claims>(
        token,
        &DecodingKey::from_secret(std::env::var("SECRET_WORD_JWT").unwrap().as_ref()),
        &validation,
    )?;
    Ok(claims.claims.id)
}

#[cfg(test)]
mod tests {
    use super::*;

    pub fn make_jwt_token(user_id: u32) -> String {
        let claims = Claims {
            id: user_id,
            exp: (Utc::now() + Duration::hours(4)).timestamp(),
        };
        jsonwebtoken::encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(b"motherfucker"),
        )
        .unwrap()
    }
    pub fn verify_jwt_token(token: &str) -> anyhow::Result<u32> {
        let validation = Validation::default();

        let claims = decode::<Claims>(
            token,
            &DecodingKey::from_secret(b"motherfucker"),
            &validation,
        )?;
        Ok(claims.claims.id)
    }

    #[test]
    fn test_verify_jwt() {
        let jwt_token = make_jwt_token(28);
        verify_jwt_token(&jwt_token).unwrap();
    }

    #[test]
    #[should_panic]
    fn test_incorrect_token() {
        let jwt_token = make_jwt_token(28);
        verify_jwt_token(&(jwt_token + "Vladivostok")).unwrap();
    }
}
