use axum::{
    extract::{Query, State},
    http::{header::AUTHORIZATION, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use sqlx::MySqlPool;

use crate::{crypt, db};

use super::{ErrorResponse, ErrorTypes};

#[derive(Serialize, Deserialize)]
pub struct QueryValidate {
    token: String,
}

#[derive(Serialize, Deserialize)]
pub struct LogoutBody {
    refresh_token: String,
}

// /token [GET] - Эндпоинт, предназначенный для обновления expired JWT Token'а с помощью Refresh Token
// Если запрос сюда возвращает 403, то со стороны фронтенд нужно выйти из аккаунта, так как refresh token закончился
pub async fn update_jwt_token(
    State(pool): State<MySqlPool>,
    headers: HeaderMap,
) -> Result<Response, Response> {
    if let Some(authorization) = headers.get(AUTHORIZATION) {
        let refresh_tkn = authorization
            .to_str()
            .unwrap()
            .split_whitespace()
            .nth(1)
            .unwrap_or("");

        if !db::tokens::token_exists(&pool, refresh_tkn).await {
            return Err((
                StatusCode::FORBIDDEN,
                axum::Json(ErrorResponse::new(
                    ErrorTypes::RefreshTokenExpired,
                    "Please, log in again",
                )),
            )
                .into_response());
        }
        match crypt::token::verify_refresh_token(refresh_tkn) {
            Ok(id) => {
                let jwt_token = crypt::token::make_jwt_token(id);
                return Ok((StatusCode::OK, jwt_token.to_string()).into_response());
            }
            Err(why) => {
                eprintln!("Error verify refresh: {}", why);
                db::tokens::delete_token(&pool, refresh_tkn).await.unwrap();
                return Err((
                    StatusCode::FORBIDDEN,
                    axum::Json(ErrorResponse::new(
                        ErrorTypes::RefreshTokenExpired,
                        "Please, log in again",
                    )),
                )
                    .into_response());
            }
        }
    }
    return Err((
        StatusCode::BAD_REQUEST,
        axum::Json(ErrorResponse::new(
            ErrorTypes::BadData,
            "Token is not suplied",
        )),
    )
        .into_response());
}

// /validate [GET] - Эндпоинт для проверки валидности JWT Токена, если возвращает 401, это значит
// Что нужно обновить JWT Токен через /token
pub async fn validate(Query(data): Query<QueryValidate>) -> Result<Response, Response> {
    match crypt::token::verify_jwt_token(&data.token) {
        Ok(_) => return Ok((StatusCode::OK).into_response()),
        Err(why) => {
            eprintln!("Error {}", why);
            return Err((
                StatusCode::UNAUTHORIZED,
                axum::Json(ErrorResponse::new(
                    ErrorTypes::JwtTokenExpired,
                    "Update JWT token",
                )),
            )
                .into_response());
        }
    };
}

// /logout [POST] - эндпоинт для выхода из аккаунта
pub async fn logout(
    State(pool): State<MySqlPool>,
    Json(data): Json<LogoutBody>,
) -> Result<Response, Response> {
    if let Err(why) = db::tokens::delete_token(&pool, &data.refresh_token).await {
        eprintln!("Err deleting rtoken: {}", why);
    }
    Ok((StatusCode::OK).into_response())
}
