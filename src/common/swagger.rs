use utoipa::OpenApi;
use crate::handlers;



pub struct SecurityAddon;
impl utoipa::Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        if let Some(components) = openapi.components.as_mut() {
            components.add_security_scheme(
                "api_key",
                utoipa::openapi::security::SecurityScheme::ApiKey(
                    utoipa::openapi::security::ApiKey::Header(
                        utoipa::openapi::security::ApiKeyValue::new("VLADIVOSTOK85000")
                    )
                ),
            );
        }
    }
}

#[derive(OpenApi)]
#[openapi(
    paths(
        handlers::auth::login,
        handlers::auth::register,
        handlers::auth::validate,
        handlers::auth::update_jwt_token,
        handlers::auth::logout,
        handlers::auth::create_reset,
        handlers::auth::reset_password,
        handlers::auth::validate_reset,
        handlers::oauth::oauth_redirect,
        handlers::oauth::oauth_authorize
    ),
    // components(
    //     schemas(UserLogin, ErrorResponse, TokensPayload)
    // ),
    modifiers(&SecurityAddon),
    tags(
        (name = "NeoTeo-Auth", description = "Один статус код может обозначать несколько ошибок, обозначены через ;. Ошибка 5xx обозначает непредвиденную ошибку. В таком случае в error_message содержится текст ошибки Раста")
    )
)]
pub struct ApiDoc;