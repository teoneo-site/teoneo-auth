use std::{any::Any, time::Duration};

use axum::{extract::FromRef, http::StatusCode, response::{IntoResponse, Response}};
use deadpool_lapin::Runtime;
use openidconnect::{core::{CoreClient, CoreProviderMetadata}, ClientId, ClientSecret, IssuerUrl, RedirectUrl};
use reqwest::ClientBuilder;
use sqlx::{mysql::MySqlPoolOptions, MySql, Pool};

use crate::common::error::{ErrorResponse, ErrorTypes};

mod crypt;
mod db;
mod handlers;
mod common;
mod clients;

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
        axum::Json(ErrorResponse::new(
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
struct BasicState {
    pool: Pool<MySql>,
    http_client: reqwest::Client,
    
}

#[derive(Clone)]
pub struct AppState {
    basic: BasicState,
    oauth_client: OIDCClient,
    rabbit: deadpool_lapin::Pool,
}

impl FromRef<AppState> for BasicState {
    fn from_ref(state: &AppState) -> Self {
        state.basic.clone()
    }
}

impl FromRef<AppState> for OIDCClient {
    fn from_ref(state: &AppState) -> Self {
        state.oauth_client.clone()
    }
}

async fn get_state(connect_str: &str) -> AppState {
    let pool = MySqlPoolOptions::new()
        .max_connections(10) // Надо подумать какое число тут использовать, мб max_hardware_concurrency()
        .acquire_timeout(Duration::from_secs(10))
        .connect(&connect_str)
        .await
        .expect("Cant connect");

    let reqwest_http_client = ClientBuilder::new()
        .user_agent("MyApp/1.0") // Always good to identify your app
        .timeout(Duration::from_secs(10)) // Total request timeout
        .connect_timeout(Duration::from_secs(5)) // Timeout for TCP handshake
        .pool_idle_timeout(Duration::from_secs(30)) // Drop idle connections
        .pool_max_idle_per_host(5) // Good default
        .redirect(reqwest::redirect::Policy::limited(5)) // Follow up to 5 redirects
        .build()
        .expect("Failed to build HTTP client");

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

    let mut cfg = deadpool_lapin::Config::default();
    cfg.url = Some(std::env::var("RABBITMQ_URL").unwrap());
    let lapin_pool = cfg.create_pool(Some(Runtime::Tokio1)).unwrap();
    
    AppState {
        basic: BasicState { pool, http_client: reqwest_http_client },
        oauth_client: client,
        rabbit: lapin_pool
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
    let app = common::routes::get_router(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8081").await.unwrap(); // TODO: port from dotenv
    tracing::info!("Server started on port 8081");
    axum::serve(listener, app).await.unwrap();
}
