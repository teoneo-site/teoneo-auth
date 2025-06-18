use std::{any::Any, time::Duration};

use axum::{error_handling::HandleErrorLayer, extract::FromRef, http::StatusCode, response::{IntoResponse, Response}, BoxError, Router};
use handlers::ErrorTypes;
use openidconnect::{core::{CoreClient, CoreProviderMetadata}, Client, ClientId, ClientSecret, IssuerUrl, RedirectUrl};
use sqlx::{mysql::MySqlPoolOptions, MySql, Pool};
use tower::{buffer::BufferLayer, limit::RateLimitLayer, ServiceBuilder};
use tower_http::{catch_panic::CatchPanicLayer, cors::CorsLayer};
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

mod crypt;
mod db;
mod handlers;

fn internal_server_error_handler(err: Box<dyn Any + Send + 'static>) -> Response {
    let details = if let Some(s) = err.downcast_ref::<String>() {
        s.clone()
    } else if let Some(s) = err.downcast_ref::<&str>() {
        s.to_string()
    } else {
        "Unknown panic message".to_string()
    };
    println!("Internal server error catched: {}", details);
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        axum::Json(handlers::ErrorResponse::new(
            ErrorTypes::InternalError,
            &details,
        )), // Should not panic, because struct is always valid for converting into JSON
    )
        .into_response()
}

type OIDCClient = openidconnect::Client<
    openidconnect::EmptyAdditionalClaims, openidconnect::core::CoreAuthDisplay, 
    openidconnect::core::CoreGenderClaim, openidconnect::core::CoreJweContentEncryptionAlgorithm, 
    openidconnect::core::CoreJsonWebKey, openidconnect::core::CoreAuthPrompt, openidconnect::StandardErrorResponse<openidconnect::core::CoreErrorResponseType>, 
    openidconnect::StandardTokenResponse<openidconnect::IdTokenFields<openidconnect::EmptyAdditionalClaims, openidconnect::EmptyExtraTokenFields, 
    openidconnect::core::CoreGenderClaim, openidconnect::core::CoreJweContentEncryptionAlgorithm, openidconnect::core::CoreJwsSigningAlgorithm>, 
    openidconnect::core::CoreTokenType>, openidconnect::StandardTokenIntrospectionResponse<openidconnect::EmptyExtraTokenFields, openidconnect::core::CoreTokenType>, 
    openidconnect::core::CoreRevocableToken, openidconnect::StandardErrorResponse<openidconnect::RevocationErrorResponseType>, 
    openidconnect::EndpointSet, openidconnect::EndpointNotSet, 
    openidconnect::EndpointNotSet, openidconnect::EndpointNotSet, openidconnect::EndpointMaybeSet, 
    openidconnect::EndpointMaybeSet>;

#[derive(Clone)]
pub struct AppState {
    pool: Pool<MySql>,
    oauth_client: OIDCClient
}

impl FromRef<AppState> for Pool<MySql> {
    fn from_ref(state: &AppState) -> Self {
        state.pool.clone()
    }
}
impl FromRef<AppState> for OIDCClient {
    fn from_ref(state: &AppState) -> Self {
        state.oauth_client.clone()
    }
}

struct SecurityAddon;
impl utoipa::Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        if let Some(components) = openapi.components.as_mut() {
            components.add_security_scheme(
                "api_key",
                utoipa::openapi::security::SecurityScheme::ApiKey(
                    utoipa::openapi::security::ApiKey::Header(
                        utoipa::openapi::security::ApiKeyValue::new("VLADIVOSTOK85000")
                    )
                ),
            );
        }
    }
}

#[derive(OpenApi)]
#[openapi(
    paths(
        handlers::login::login,
        handlers::register::register,
        handlers::token::validate,
        handlers::token::update_jwt_token,
        handlers::token::logout,
        handlers::password::create_reset,
        handlers::password::reset_password,
        handlers::password::validate_reset,
        handlers::oauth::oauth_redirect,
        handlers::oauth::oauth_authorize
    ),
    // components(
    //     schemas(UserLogin, ErrorResponse, TokensPayload)
    // ),
    modifiers(&SecurityAddon),
    tags(
        (name = "NeoTeo-Auth", description = "Один статус код может обозначать несколько ошибок, обозначены через ;. Ошибка 5xx обозначает непредвиденную ошибку. В таком случае в error_message содержится текст ошибки Раста")
    )
)]
struct ApiDoc;


fn get_router(state: AppState) -> Router {
    Router::new()
    .route(
        "/auth/register",
        axum::routing::post(handlers::register::register),
    )
    .route("/auth/login", axum::routing::post(handlers::login::login))
    .route(
        "/auth/token",
        axum::routing::get(handlers::token::update_jwt_token),
    )
    .route(
        "/auth/validate",
        axum::routing::get(handlers::token::validate),
    )
    .route("/auth/logout", axum::routing::post(handlers::token::logout))
    .route(
        "/auth/reset/validate",
        axum::routing::get(handlers::password::validate_reset),
    )
    .route(
        "/auth/reset",
        axum::routing::post(handlers::password::create_reset),
    )
    .route(
        "/auth/reset/password",
        axum::routing::post(handlers::password::reset_password),
    )
    .route(
        "/auth/oauth/redirect/google",
        axum::routing::get(handlers::oauth::oauth_redirect)
    )
    .route(
        "/auth/oauth/callback/google",
        axum::routing::post(handlers::oauth::oauth_authorize)
    )
    .layer(CorsLayer::permissive()) // Для того чтоб CORS мозг не ебал
    .layer(CatchPanicLayer::custom(internal_server_error_handler))
    .layer(
        ServiceBuilder::new()
            .layer(HandleErrorLayer::new(|err: BoxError| async move {
                // So compiler wont complain about some Infallable Trait shit
                eprintln!("{}", err);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    axum::Json(handlers::ErrorResponse::new(
                        ErrorTypes::InternalError,
                        "Internal error occured",
                    )),
                )
            }))
            .layer(BufferLayer::new(1024)) // Means it can process 1024 messages before backpressure is applied TODO: Adjust
            .layer(RateLimitLayer::new(5, Duration::from_secs(1))), // Rate limti does not impl Clone, so we need to use BufferLayer TODO: Adjust
    )
    .merge(SwaggerUi::new("/docs").url("/api-doc/openapi.json", ApiDoc::openapi()))
    .with_state(state)
}

async fn get_state(connect_str: &str) -> AppState {
    let pool = MySqlPoolOptions::new()
        .max_connections(10) // Надо подумать какое число тут использовать, мб max_hardware_concurrency()
        .acquire_timeout(Duration::from_secs(10))
        .connect(&connect_str)
        .await
        .expect("Cant connect");

    let google_client_id = ClientId::new(std::env::var("GOOGLE_CLIENT_ID").expect("Missing the GOOGLE_CLIENT_ID env variable"));
    let google_client_secret = ClientSecret::new(std::env::var("GOOGLE_SECRET_KEY").expect("MISSING GOOGLE_SECRET_KEY env var"));
    let issuer_url = IssuerUrl::new("https://accounts.google.com".to_string()).unwrap();

    let http_client = reqwest::ClientBuilder::new()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    
    let provider_data = CoreProviderMetadata::discover_async(issuer_url, &http_client)
        .await
        .unwrap();
    let client = CoreClient::from_provider_metadata(provider_data, google_client_id, Some(google_client_secret))
        .set_redirect_uri(RedirectUrl::new("http://localhost:8081/auth/oauth/callback/google".to_string()).unwrap());

    AppState {
        pool,
        oauth_client: client,
    }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init(); // Для логирования всяких штук
    dotenv::dotenv().ok();
    tracing::info!("Starting auth service");
    tracing::info!("Loaded DATABASE_URL: {:?}", std::env::var("DATABASE_URL"));
    tracing::info!("Loaded GOOGLE_CLIENT_ID: {:?}", std::env::var("GOOGLE_CLIENT_ID"));
    let connect_str = std::env::var("DATABASE_URL").unwrap(); // TODO: get from dotenv

    let state = get_state(&connect_str).await;
    let app = get_router(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8081").await.unwrap(); // TODO: port from dotenv
    tracing::info!("Server started on port 8081");
    axum::serve(listener, app).await.unwrap();
}


/*
version: "3.8"

services:
  teoneo-auth:
    image: teoneo-auth
    ports:
      - "8081:8081"
    environment:
      - AES_KEY=f3c2a1e4b5d6e7f8a9b0c1d2e3f4a5b6
      - SECRET_WORD_JWT=VLADIVOSTOK
      - SECRET_WORD_REFRESH=VLADIVOSTOK2000
      # Добавь свои переменные окружения сюда
      # Пример:
      # - DATABASE_URL=postgres://user:pass@db:5432/mydb
      # - SECRET_KEY=supersecret
*/