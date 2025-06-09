use std::{any::Any, time::Duration};

use axum::{error_handling::HandleErrorLayer, http::StatusCode, response::{IntoResponse, Response}, BoxError, Router};
use handlers::ErrorTypes;
use sqlx::mysql::MySqlPoolOptions;
use tower::{buffer::BufferLayer, limit::RateLimitLayer, ServiceBuilder};
use tower_http::{catch_panic::CatchPanicLayer, cors::CorsLayer};

mod crypt;
mod db;
mod handlers;

// Если с каких-то других микросервисов будет приходить ошибка 401 - значит нужно обновить JWT Token
// И только при 403 ошибке нужно принудительно выкидывать пользователя из аккаунта
// Таким образом достигается максимальная безопасность

/*  ## Про модули:
db - используется для написания функций для взаимодействия с базой данных
1. tokens - взаимодействие с таблицей refresh_tokens
2. users - взаимодействие с таблицей users

handlers - для написания функций для разных типов эндпоинтов
1. login - очевидео
2. register - очевидно
3. token - для обновления токенов и выход из аккаунта (т.к выход из аккаунта тесно связан с токенами)

crypt - модуль, в котором находятся различные типы шифрования для различных вещей
1. encryption - хз зачем
2. password - очевидно
3. token - шифрование JWt и Refresh tokenов и их проверка на валидность (т.е не подделан и срок годности не истек)
*/

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


#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init(); // Для логирования всяких штук
    dotenv::dotenv().ok();

    let connect_str = std::env::var("DATABASE_URL").unwrap(); // TODO: get from dotenv

    let mysql_pool = MySqlPoolOptions::new()
        .max_connections(10) // Надо подумать какое число тут использовать, мб max_hardware_concurrency()
        .acquire_timeout(Duration::from_secs(10))
        .connect(&connect_str)
        .await
        .expect("Cant connect");

    let app = Router::new()
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
        .with_state(mysql_pool);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8081").await.unwrap(); // TODO: port from dotenv
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