use serde::Serialize;

// Payloads

#[derive(Serialize)]
pub struct TokensPayload {
    pub jwt_token: String,
    pub refresh_token: String,
}
