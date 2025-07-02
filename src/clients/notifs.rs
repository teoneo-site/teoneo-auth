use deadpool_lapin::lapin::{BasicProperties, options::BasicPublishOptions};
use lettre::{Message, message::header::ContentType};
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize)]
pub struct MessageJSON {
    email: String, // Кому отправить сообщение
    subject: String,
    message: String, // Полный текст сообщения, который нужно отправить
}

const EMAIL_EXCHANGE: &str = "email-exchange";
const EMAIL_ROUTE_KEY: &str = "email-route";

pub async fn send_email(
    pool: &deadpool_lapin::Pool,
    email: &str,
    subject: &str,
    message: &str,
) -> anyhow::Result<()> {
    todo!("Impl notifs service");
    let msg = MessageJSON {
        email: email.to_owned(),
        subject: subject.to_owned(),
        message: message.to_owned(),
    };
    let msg_str = serde_json::to_string(&msg)?;

    let conn = pool.get().await?;
    let channel = conn.create_channel().await?;
    channel
        .basic_publish(
            EMAIL_EXCHANGE,
            EMAIL_ROUTE_KEY,
            BasicPublishOptions::default(),
            msg_str.as_bytes(),
            BasicProperties::default(),
        )
        .await?;

    Ok(())
}
