use serde::Serialize;
use utoipa::ToSchema;

// Payloads

#[derive(Serialize, ToSchema)]
pub struct TokensPayload {
    pub jwt_token: String,
    pub refresh_token: String,
}
