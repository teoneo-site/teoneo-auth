use std::time::Duration;

use axum::{
    Json,
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use lettre::{
    Message, SmtpTransport, Transport, message::header::ContentType,
    transport::smtp::authentication::Credentials,
};
use reqwest::header::AUTHORIZATION;
use serde::{Deserialize, Serialize};
use sqlx::{MySql, MySqlPool, Pool};
use utoipa::ToSchema;

use crate::{
    clients, common::error::{AppError, ErrorResponse, ErrorTypes}, crypt::{self, encryption::create_reset_token}, db, error_response, AppState, BasicState
};

#[derive(Serialize, ToSchema)]
pub struct TokensPayload {
    pub jwt_token: String,
    pub refresh_token: String,
}

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
    State(state): State<BasicState>,
    Json(user_data): Json<UserLogin>,
) -> Result<Response, AppError> {
    if (user_data.password.is_empty()
        || user_data.password.len() < 4
        || user_data.password.len() > 64)
        || (user_data.email.is_empty())
    {
        return Ok(error_response!(
            StatusCode::BAD_REQUEST,
            ErrorTypes::BadData,
            "Provided data is bad"
        ));
    }
    let user_id = match db::users::id_by_email(&state.pool, &user_data.email).await {
        Ok(id) => id,
        Err(why) => {
            tracing::error!("{}", why);
            return Ok(error_response!(
                StatusCode::BAD_REQUEST,
                ErrorTypes::UserNotExists,
                "User does not exist, please register"
            ));
        }
    };
    let user_password_hash = db::users::get_password_hash(&state.pool, user_id)
        .await
        .unwrap(); // User exists 100% by now so does the password hash

    match crypt::password::verify_password(&user_data.password, &user_password_hash) {
        Ok(()) => {
            let jwt_token = crypt::token::make_jwt_token(user_id);
            let refresh_token = crypt::token::make_refresh_token(user_id);

            db::tokens::create_token(&state.pool, user_id, &refresh_token)
                .await
                .unwrap(); // I mean it cant really fail but anyway TODO: handle this

            let resp = TokensPayload {
                jwt_token,
                refresh_token,
            };
            return Ok((StatusCode::OK, axum::Json(resp)).into_response());
        }
        Err(why) => {
            tracing::error!("Error verify: {}", why);

            return Ok(error_response!(
                StatusCode::UNAUTHORIZED,
                ErrorTypes::BadData,
                "Invalid credentials"
            ));
        }
    }
}

#[derive(Deserialize, Serialize, ToSchema)]
pub struct UserRegister {
    pub username: String,
    pub email: String,
    pub password: String,
}


#[utoipa::path(
    post,
    path = "/auth/register",
    request_body = UserRegister,
    responses(
        (status = 201, description = "Успешная регистрация", body = TokensPayload),
        (status = 400, description = "Какое-то из полей слишком короткое/длинное и т.д;Пользователя не существует", body = ErrorResponse),
        (status = 409, description = "Не получилось создать аккаунт, такой уже существует (дубликат почты)", body = ErrorResponse)
    )
)]
pub async fn register(
    State(state): State<BasicState>,
    Json(user_data): Json<UserRegister>,
) -> Result<Response, AppError> {
    if (user_data.username.len() > 32 || user_data.username.is_empty())
        || (user_data.password.is_empty()
            || user_data.password.len() < 4
            || user_data.password.len() > 64)
        || (user_data.email.is_empty())
    {
        return Ok(error_response!(
            StatusCode::BAD_REQUEST,
            ErrorTypes::BadData,
            "Provided data is bad"
        ));
    }
    let hashed_password = crypt::password::hash_password(&user_data.password);

    match db::users::create_user(
        &state.pool,
        &user_data.username,
        &user_data.email,
        &hashed_password,
    )
    .await
    {
        Ok(id) => {
            let jwt_token = crypt::token::make_jwt_token(id);
            let refresh_token = crypt::token::make_refresh_token(id);

            db::tokens::create_token(&state.pool, id, &refresh_token)
                .await
                .unwrap(); // May wanna handle this

            let resp = TokensPayload {
                jwt_token,
                refresh_token,
            };
            return Ok((StatusCode::CREATED, axum::Json(resp)).into_response());
        }
        Err(why) => {
            tracing::error!("Error registering: {}", why);

            Ok(error_response!(
                StatusCode::CONFLICT,
                ErrorTypes::UserAlreadyExists,
                "User is already registered"
            ))
        }
    }
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct ValidateTokenBody {
    token: String,
}

#[utoipa::path(
    post,
    description = "Используется для подтверждения того, что ресет токен еще не истек/не использован",
    path = "/auth/reset/validate",
    request_body = ValidateTokenBody,
    responses(
        (status = 200, description = "Все валидно"),
        (status = 403, description = "Ресет токен истек/был использован", body = ErrorResponse),
    )
)]
pub async fn validate_reset(
    State(state): State<BasicState>,
    Query(token_data): Query<ValidateTokenBody>,
) -> Result<Response, AppError> {
    match db::reset_tokens::validate_token(&state.pool, &token_data.token).await {
        Ok(_) => return Ok((StatusCode::OK).into_response()),
        Err(why) => {
            tracing::error!("{}", why);
            Ok(error_response!(
                StatusCode::FORBIDDEN,
                ErrorTypes::InvalidResetToken,
                "Reset token is no longer valid"
            ))
        }
    }
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct CreateResetBody {
    email: String,
}

#[utoipa::path(
    post,
    description = "Используется при нажатии на сбросить пароль. Создает reset токен и отсылает сообщение на почту",
    path = "/auth/reset",
    request_body = CreateResetBody,
    responses(
        (status = 200, description = "Сообщение было успешно отправлено (наверное)"),
        (status = 404, description = "Юзера не существует", body = ErrorResponse)
    )
)]
pub async fn create_reset(
    State(state): State<AppState>,
    Json(data): Json<CreateResetBody>,
) -> anyhow::Result<Response, AppError> {
    if let Err(why) = db::users::email_exists(&state.basic.pool, &data.email).await {
        tracing::error!("Such user does not exist: {}", why);
        return Ok(error_response!(
            StatusCode::NOT_FOUND,
            ErrorTypes::UserNotExists,
            "Such email does not exist"
        ));
    }

    let token = create_reset_token();

    db::reset_tokens::insert_token(&state.basic.pool, &data.email, &token).await?;

    clients::notifs::send_email(
        &state.rabbit,
        &data.email,
        "Восстановление пароля",
        &format!(
            "Ссылка для восстановления пароля: http://5.129.200.137/new-password?token={}",
            token
        ),
    )
    .await?;
    return Ok((StatusCode::OK).into_response());
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct ResetPasswordBody {
    token: String,
    password: String,
}

#[utoipa::path(
    post,
    description = "Используется при переходе по ссылке из почты и отправки нового пароля (изменяет пароль пользователя)",
    path = "/auth/reset/password",
    request_body = ResetPasswordBody,
    responses(
        (status = 200, description = "Пароль успешно обновлен"),
        (status = 403, description = "Ресет токен истек. Пользователю снова надо запросить восстановление пароля", body = ErrorResponse),
    )
)]
pub async fn reset_password(
    State(state): State<BasicState>,
    Json(data): Json<ResetPasswordBody>,
) -> anyhow::Result<Response, AppError> {
    match db::reset_tokens::validate_token(&state.pool, &data.token).await {
        Ok(email) => {
            let hashed_password = crypt::password::hash_password(&data.password);
            db::users::set_password_by_email(&state.pool, &email, &hashed_password)
                .await
                .unwrap();
            db::reset_tokens::remove_token(&state.pool, &data.token).await;
            return Ok((StatusCode::OK).into_response());
        }
        Err(why) => {
            tracing::error!("{}", why);
            db::reset_tokens::remove_token(&state.pool, &data.token).await;
            return Ok(error_response!(
                StatusCode::FORBIDDEN,
                ErrorTypes::InvalidResetToken,
                "Reset token is no longer valid"
            ));
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct QueryValidate {
    token: String,
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct LogoutBody {
    refresh_token: String,
}

// /token [GET] - Эндпоинт, предназначенный для обновления expired JWT Token'а с помощью Refresh Token
// Если запрос сюда возвращает 403, то со стороны фронтенд нужно выйти из аккаунта, так как refresh token закончился
#[utoipa::path(
    get,
    description = "Эндпоинт, предназначенный для обновления expired JWT Token'а с помощью Refresh Token",
    path = "/auth/token",
    params(
        ("Authorization" = String, Header, description = "JWT")
    ),
    responses(
        (status = 200, description = "Токен обновлен. Присылается просто токен текстом", body = String),
        (status = 403, description = "Refresh token истек, нужно выкинуть юзера из акка; При проверке рефреша произошла ошибка", body = ErrorResponse),
        (status = 400, description = "Нет заголовка Authorization", body = ErrorResponse)
    )
)]
pub async fn update_jwt_token(
    State(state): State<BasicState>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    if let Some(authorization) = headers.get(AUTHORIZATION) {
        let refresh_tkn = authorization
            .to_str()
            .unwrap()
            .split_whitespace()
            .nth(1)
            .unwrap_or("");

        if !db::tokens::token_exists(&state.pool, refresh_tkn).await {
            tracing::error!("Token does not exist in DB");
            return Ok(error_response!(
                StatusCode::FORBIDDEN,
                ErrorTypes::RefreshTokenExpired,
                "Please, log in again"
            ));
        }
        match crypt::token::verify_refresh_token(refresh_tkn) {
            Ok(id) => {
                let jwt_token = crypt::token::make_jwt_token(id);
                return Ok((StatusCode::OK, jwt_token.to_string()).into_response());
            }
            Err(why) => {
                tracing::error!("Error verify refresh: {}", why);
                db::tokens::delete_token(&state.pool, refresh_tkn)
                    .await
                    .unwrap();
                return Ok(error_response!(
                    StatusCode::FORBIDDEN,
                    ErrorTypes::RefreshTokenExpired,
                    "Please, log in again"
                ));
            }
        }
    }

    Ok(error_response!(
        StatusCode::BAD_REQUEST,
        ErrorTypes::BadData,
        "Token is not suplied"
    ))
}

// /validate [GET] - Эндпоинт для проверки валидности JWT Токена, если возвращает 401, это значит
// Что нужно обновить JWT Токен через /token
#[utoipa::path(
    get,
    path = "/auth/validate",
    description = "Эндпоинт для проверки валидности JWT Токена",
    // request_body = UserRegister,
    params (
        ("token" = String, Query, description = "JWT токен пользователя")
    ),
    responses(
        (status = 201, description = "Успешная регистрация"),
        (status = 401, description = "Токен истек", body = ErrorResponse),
    )
)]
pub async fn validate(Query(data): Query<QueryValidate>) -> Result<Response, AppError> {
    if let Err(why) = crypt::token::verify_jwt_token(&data.token) {
        tracing::error!("Error {}", why);
        return Ok(error_response!(
            StatusCode::UNAUTHORIZED,
            ErrorTypes::JwtTokenExpired,
            "Update JWT token"
        ));
    }
    Ok((StatusCode::OK).into_response())
}

// /logout [POST] - эндпоинт для выхода из аккаунта
#[utoipa::path(
    post,
    description = "Эндпоинт для выхода из аккаунта. Токен поставляется в хедерах",
    path = "/auth/logout",
    params(
        ("Authorization" = String, Header, description = "JWT")
    ),
    request_body = LogoutBody,
    responses(
        (status = 200, description = "Успешный выход"),
    )
)]
pub async fn logout(
    State(state): State<BasicState>,
    Json(data): Json<LogoutBody>,
) -> Result<Response, AppError> {
    if let Err(why) = db::tokens::delete_token(&state.pool, &data.refresh_token).await {
        tracing::error!("Err deleting rtoken: {}", why);
    }
    Ok((StatusCode::OK).into_response())
}
