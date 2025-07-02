use std::time::Duration;

use axum::{error_handling::HandleErrorLayer, BoxError, Router};
use reqwest::StatusCode;
use tower::{buffer::BufferLayer, limit::RateLimitLayer, ServiceBuilder};
use tower_http::{catch_panic::CatchPanicLayer, cors::CorsLayer};
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

use crate::{common::{error::{internal_server_error_handler, ErrorResponse, ErrorTypes}, swagger::ApiDoc}, handlers, AppState};


fn auth_routes() -> Router<AppState> {
    Router::new()
    .route(
        "/auth/register",
        axum::routing::post(handlers::auth::register),
    )
    .route("/auth/login", axum::routing::post(handlers::auth::login))
    .route(
        "/auth/token",
        axum::routing::get(handlers::auth::update_jwt_token),
    )
    .route(
        "/auth/validate",
        axum::routing::get(handlers::auth::validate),
    )
    .route("/auth/logout", axum::routing::post(handlers::auth::logout))
    .route(
        "/auth/reset/validate",
        axum::routing::get(handlers::auth::validate_reset),
    )
    .route(
        "/auth/reset",
        axum::routing::post(handlers::auth::create_reset),
    )
    .route(
        "/auth/reset/password",
        axum::routing::post(handlers::auth::reset_password),
    )
}

fn oauth_routes() -> Router<AppState> {
    Router::new()
    .route(
        "/auth/oauth/redirect/google",
        axum::routing::get(handlers::oauth::oauth_redirect)
    )
    .route(
        "/auth/oauth/callback/google",
        axum::routing::post(handlers::oauth::oauth_authorize)
    ) 
}


pub fn get_router(state: AppState) -> Router {
    Router::new()
    .merge(auth_routes())
    .merge(oauth_routes())
    .layer(CorsLayer::permissive()) // Для того чтоб CORS мозг не ебал
    .layer(CatchPanicLayer::custom(internal_server_error_handler))
    .layer(
        ServiceBuilder::new()
            .layer(HandleErrorLayer::new(|err: BoxError| async move {
                // So compiler wont complain about some Infallable Trait shit
                eprintln!("{}", err);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    axum::Json(ErrorResponse::new(
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