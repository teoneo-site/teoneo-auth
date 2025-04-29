use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use sqlx::MySqlPool;

use crate::{crypt, db};

use super::types::{AuthError, AuthErrors, TokensPayload};

#[derive(Serialize, Deserialize)]
pub struct UserLogin {
    email: String,
    password: String,
}

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
            Json(AuthError::new(AuthErrors::BadData, "Provided data is bad")),
        )
            .into_response());
    }
    let user_id = match db::user::id_by_email(&pool, &user_data.email).await {
        Ok(id) => id,
        Err(why) => {
            eprintln!("{}", why);
            return Err((
                StatusCode::BAD_REQUEST,
                Json(AuthError::new(
                    AuthErrors::UserNotExists,
                    "User does not exist, please register",
                )),
            )
                .into_response());
        }
    };
    let user_password_hash = db::user::get_password_hash(&pool, user_id).await.unwrap(); // User exists 100% by now so does the password hash

    match crypt::password::verify_password(&user_data.password, &user_password_hash) {
        Ok(()) => {
            let jwt_token = crypt::token::make_jwt_token(user_id);
            let refresh_token = crypt::token::make_refresh_token(user_id);

            db::token::create_token(&pool, user_id, &refresh_token)
                .await
                .unwrap();

            let resp = TokensPayload {
                jwt_token,
                refresh_token,
            };
            return Ok((StatusCode::OK, Json(resp)).into_response());
        }
        Err(why) => {
            eprintln!("Error verify: {}", why);
            return Err((
                StatusCode::UNAUTHORIZED,
                Json(AuthError::new(
                    AuthErrors::InvalidCreds,
                    "Invalid credentials",
                )),
            )
                .into_response());
        }
    }
}
