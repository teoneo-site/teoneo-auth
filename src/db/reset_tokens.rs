use sqlx::{MySqlPool, Row};

pub async fn insert_token(pool: &MySqlPool, email: &str, token: &str) -> anyhow::Result<()> {
    sqlx::query("INSERT INTO reset_tokens (user_email, token) VALUES (?, ?)")
        .bind(email)
        .bind(token)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn validate_token(pool: &MySqlPool, token: String) -> anyhow::Result<String> {
    let row = sqlx::query("SELECT user_email FROM reset_tokens WHERE token = ?")
        .bind(token)
        .fetch_one(pool)
        .await?;
    Ok(row.try_get::<String, _>(0)?)
}
