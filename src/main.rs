

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    dotenv::dotenv().ok();

    let connect_str = "mysql://klewy:root@localhost:3306/pm"; // TODO: Make dotenv


}