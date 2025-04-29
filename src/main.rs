use std::time::Duration;

use axum::{extract::DefaultBodyLimit, Router};
use sqlx::mysql::MySqlPoolOptions;

mod handlers;
mod crypt;
mod db;

// Если с каких-то других микросервисов будет приходить ошибка 401 - значит нужно обновить JWT Token
// И только при 403 ошибке нужно принудительно выкидывать пользователя из аккаунта
// Таким образом достигается максимальная безопасность

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    dotenv::dotenv().ok();

    let connect_str = "mysql://klewy:root@localhost:3306/pm"; // TODO: get from dotenv

    let mysql_pool = MySqlPoolOptions::new()
        .max_connections(10)
        .acquire_timeout(Duration::from_secs(10))
        .connect(connect_str)
        .await
        .expect("Cant connect");

    let app = Router::new()
    .route("/register", axum::routing::post(handlers::register::register))
    .route("/login", axum::routing::post(handlers::login::login))
    .route("/token", axum::routing::get(handlers::token::update_jwt_token))
    .route("/validate", axum::routing::get(handlers::token::validate))
    .route("/logout", axum::routing::post(handlers::token::logout))
    .with_state(mysql_pool);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8081").await.unwrap(); // TODO: port from dotenv
    axum::serve(listener, app).await.unwrap();
}