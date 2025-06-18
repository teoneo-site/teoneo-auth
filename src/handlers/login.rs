use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use sqlx::MySqlPool;
use utoipa::ToSchema;

use crate::{crypt, db};

use super::{types::TokensPayload, ErrorResponse, ErrorTypes};

#[derive(Serialize, Deserialize, ToSchema)]
pub struct UserLogin {
    email: String,
    password: String,
}


#[utoipa::path(
    post,
    path = "/auth/login",
    request_body = UserLogin,
    responses(
        (status = 200, description = "Успешный вход в аккаунт", body = TokensPayload),
        (status = 400, description = "Какое-то из полей слишком короткое/длинное и т.д;Пользователя не существует", body = ErrorResponse),
        (status = 401, description = "Не получилось войти в аккаунт, данные некорректны", body = ErrorResponse)
    )
)]
pub async fn login(
    State(pool): State<MySqlPool>,
    Json(user_data): Json<UserLogin>,
) -> Result<Response, Response> {
    if (user_data.password.is_empty()
        || user_data.password.len() < 4
        || user_data.password.len() > 64)
        || (user_data.email.is_empty())
    {
        return Err((
            StatusCode::BAD_REQUEST,
            axum::Json(ErrorResponse::new(
                ErrorTypes::BadData,
                "Provided data is incorrectly formatted. Password must be < 4 > 64 and email not empty",
            )),
        )
            .into_response());
    }
    let user_id = match db::users::id_by_email(&pool, &user_data.email).await {
        Ok(id) => id,
        Err(why) => {
            eprintln!("{}", why);
            return Err((
                StatusCode::BAD_REQUEST,
                axum::Json(ErrorResponse::new(
                    ErrorTypes::UserNotExists,
                    "User does not exist. Can't get their email",
                )),
            )
                .into_response());
        }
    };
    let user_password_hash = db::users::get_password_hash(&pool, user_id).await.unwrap(); // User exists 100% by now so does the password hash

    match crypt::password::verify_password(&user_data.password, &user_password_hash) {
        Ok(()) => {
            let jwt_token = crypt::token::make_jwt_token(user_id);
            let refresh_token = crypt::token::make_refresh_token(user_id);

            db::tokens::create_token(&pool, user_id, &refresh_token)
                .await
                .unwrap(); // I mean it cant really fail but anyway TODO: handle this

            let resp = TokensPayload {
                jwt_token,
                refresh_token,
            };
            return Ok((StatusCode::OK, axum::Json(resp)).into_response());
        }
        Err(why) => {
            eprintln!("Error verify: {}", why);
            return Err((
                StatusCode::UNAUTHORIZED,
                axum::Json(ErrorResponse::new(
                    ErrorTypes::BadData,
                    "Invalid credentials",
                )),
            )
                .into_response());
        }
    }
}
