use std::time::Duration;

use axum::Router;
use sqlx::mysql::MySqlPoolOptions;
use tower_http::cors::CorsLayer;

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


#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init(); // Для логирования всяких штук
    dotenv::dotenv().ok();

    let connect_str = "mysql://klewy:root@localhost:3306/teoneo"; // TODO: get from dotenv

    let mysql_pool = MySqlPoolOptions::new()
        .max_connections(10) // Надо подумать какое число тут использовать, мб max_hardware_concurrency()
        .acquire_timeout(Duration::from_secs(10))
        .connect(connect_str)
        .await
        .expect("Cant connect");


    let app = Router::new()
        .route(
            "/register",
            axum::routing::post(handlers::register::register),
        )
        .route("/login", axum::routing::post(handlers::login::login))
        .route(
            "/token",
            axum::routing::get(handlers::token::update_jwt_token),
        )
        .route("/validate", axum::routing::get(handlers::token::validate))
        .route("/logout", axum::routing::post(handlers::token::logout))
        .layer(CorsLayer::permissive()) // Для того чтоб CORS мозг не ебал
        .with_state(mysql_pool);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8081").await.unwrap(); // TODO: port from dotenv
    axum::serve(listener, app).await.unwrap();
}
