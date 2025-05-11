use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use sqlx::MySqlPool;

use crate::{crypt, db};

use super::{types::TokensPayload, ErrorResponse, ErrorTypes, ResponseBody};

#[derive(Deserialize, Serialize)]
pub struct UserRegister {
    pub username: String,
    pub email: String,
    pub password: String,
}

pub async fn register(
    State(pool): State<MySqlPool>,
    Json(user_data): Json<UserRegister>,
) -> Result<Response, Response> {
    if (user_data.username.len() > 32 || user_data.username.is_empty())
        || (user_data.password.is_empty()
            || user_data.password.len() < 4
            || user_data.password.len() > 64)
        || (user_data.email.is_empty())
    {
        return Err(ResponseBody::new(
            StatusCode::BAD_REQUEST,
            None,
            ErrorResponse::new(ErrorTypes::BadData, "Provided data is bad")
        )
            .into_response());
    }
    let hashed_password = crypt::password::hash_password(&user_data.password);

    match db::users::create_user(
        &pool,
        &user_data.username,
        &user_data.email,
        &hashed_password,
    )
    .await
    {
        Ok(id) => {
            let jwt_token = crypt::token::make_jwt_token(id);
            let refresh_token = crypt::token::make_refresh_token(id);

            db::tokens::create_token(&pool, id, &refresh_token)
                .await
                .unwrap(); // May wanna handle this

            let resp = TokensPayload {
                jwt_token,
                refresh_token,
            };
            return Ok(ResponseBody::new(StatusCode::CREATED, None, resp).into_response());
        }
        Err(why) => {
            eprintln!("Error registering: {}", why);
            return Err(ResponseBody::new(
                StatusCode::CONFLICT,
                None,
                ErrorResponse::new(
                    ErrorTypes::UserAlreadyExists,
                    "User is already registered",
                ),
            )
                .into_response());
        }
    }
}
