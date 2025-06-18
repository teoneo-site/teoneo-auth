use axum::{
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Redirect, Response},
    Json,
};
use axum_extra::extract::{cookie::Cookie, CookieJar};
use once_cell::sync::Lazy;
use openidconnect::{core::{CoreClient, CoreProviderMetadata, CoreResponseType}, AuthenticationFlow, AuthorizationCode, Client, ClientId, ClientSecret, CsrfToken, IssuerUrl, Nonce, RedirectUrl, Scope};
use serde::{Deserialize, Serialize};
use sqlx::MySqlPool;
use utoipa::ToSchema;

use crate::{crypt, db, AppState, OIDCClient};

use super::{types::TokensPayload, ErrorResponse, ErrorTypes};


#[utoipa::path(
    get,
    description = "эндпоинт перенаправляет пользователя на страницу авторизации в Гугл",
    path = "/auth/oauth/redirect/google",
    responses(
        (status = 103, description = "Перенаправление"),
        (status = 500, description = "Возникла ошибка какая-то внутри сервера"),
    )
)]
pub async fn oauth_redirect(State(client) : State<OIDCClient>) -> (CookieJar, Redirect) {
    let (auth_url, csrf, nonce) = client
        .authorize_url(AuthenticationFlow::<CoreResponseType>::AuthorizationCode, CsrfToken::new_random, Nonce::new_random)
        .add_scope(Scope::new("email".to_string()))
        .add_scope(Scope::new("profile".to_string()))
        .url();
    let cookie_jar = CookieJar::new();    
    let csrf_cookie = Cookie::build(("csrf_token", csrf.secret().clone()))
        .http_only(true)
        .build();
    let nonce_cookie = Cookie::build(("nonce_token", nonce.secret().clone()))
        .http_only(true)
        .build();
    let new_cookie_jar = cookie_jar.add(csrf_cookie).add(nonce_cookie);
    (new_cookie_jar, Redirect::to(auth_url.as_str()))
}


#[derive(Serialize, Deserialize, ToSchema)]
pub struct OAuthData {
    state: String,
    code: String,
}


#[utoipa::path(
    post,
    description = "используется после коллбэка для авторизации (для получения токенов) с помощью данных, переданных от гугла",
    path = "/auth/oauth/callback/google",
    request_body = OAuthData,
    responses(
        (status = 200, description = "Успешно. Был совершен вход в аккаунт", body = TokensPayload),
        (status = 201, description = "Успешно. Была совершена регистрация аккаунта (Если не было).", body = TokensPayload),
    )
)]
pub async fn oauth_authorize(State(state) : State<AppState>, cookies : CookieJar, Json(data) : Json<OAuthData>) -> Result<Response, Response> {
    let http_client = reqwest::ClientBuilder::new()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();

    let token_response = state.oauth_client
        .exchange_code(AuthorizationCode::new(data.code))
        .unwrap() 
        .request_async(&http_client)
        .await.unwrap(); 
    let id_token_verifier = state.oauth_client.id_token_verifier();


    let nonce_cookie = match cookies.get("nonce_token") {
        Some(cookie) => cookie,
        None => {
            eprintln!("Cookie are missing");
            return Err((
            StatusCode::BAD_REQUEST,
            axum::Json(ErrorResponse::new(
                ErrorTypes::CookieMissing,
                "Cookies were not found",
                )),
            )
                .into_response());
        }
    };


    let nonce = Nonce::new(nonce_cookie.value().to_string());
    let id_tokens_claims = token_response
        .extra_fields()
        .id_token()
        .expect("Server did not return a token")
        .claims(&id_token_verifier, &nonce)
        .unwrap();
    
    let email = id_tokens_claims.email().unwrap().to_string();

    if let Ok(_) = db::users::email_exists(&state.pool, &email).await { // Means user is already registered
        let user_id = db::users::id_by_email(&state.pool, &email).await.unwrap();

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

    let pg = passwords::PasswordGenerator::new().length(16).numbers(true).lowercase_letters(true).uppercase_letters(true).symbols(true).spaces(true).exclude_similar_characters(true).strict(true);
    let password = pg.generate_one().unwrap();
    let username = email.split('@').next().unwrap(); // There is 100% something  befoere @
    let password_hash = crypt::password::hash_password(&password);

    let id = db::users::create_user(
        &state.pool,
        &username,
        &email,
        &password_hash,
    )
    
    .await.unwrap(); // Не должно проваливаться, т.к пользователя в БД точно нет.
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