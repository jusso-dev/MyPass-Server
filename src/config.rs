/// Typed application configuration loaded from environment variables.
///
/// Secrets (HMAC key, database URL, FCM credentials) are read from env vars and
/// never logged. The server panics at startup if required vars are missing or
/// fail validation.
use std::env;

#[derive(Clone)]
pub struct AppConfig {
    pub database_url: String,
    pub hmac_key: String,
    pub fcm_project_id: Option<String>,
    pub fcm_client_email: Option<String>,
    pub fcm_private_key: Option<String>,
    pub port: u16,
    pub cors_origin: Option<String>,
}

/// Minimum acceptable HMAC key length (hex chars). 64 hex chars = 256 bits =
/// the SHA-256 block size, which is the only key length that buys cryptographic
/// strength here.
const MIN_HMAC_KEY_HEX_LEN: usize = 64;

impl AppConfig {
    /// Load configuration from environment variables.
    ///
    /// Required: `DATABASE_URL`, `HMAC_KEY`
    /// Optional: `FCM_PROJECT_ID`, `FCM_CLIENT_EMAIL`, `FCM_PRIVATE_KEY`, `PORT`, `CORS_ORIGIN`
    ///
    /// Panics if required vars are unset or if `HMAC_KEY` is too short / not hex.
    pub fn from_env() -> Self {
        let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");
        let hmac_key = env::var("HMAC_KEY").expect("HMAC_KEY must be set");

        validate_hmac_key(&hmac_key);

        Self {
            database_url,
            hmac_key,
            fcm_project_id: env::var("FCM_PROJECT_ID").ok().filter(|s| !s.is_empty()),
            fcm_client_email: env::var("FCM_CLIENT_EMAIL").ok().filter(|s| !s.is_empty()),
            fcm_private_key: env::var("FCM_PRIVATE_KEY").ok().filter(|s| !s.is_empty()),
            port: env::var("PORT")
                .ok()
                .and_then(|p| p.parse().ok())
                .unwrap_or(3000),
            cors_origin: env::var("CORS_ORIGIN").ok().filter(|s| !s.is_empty()),
        }
    }
}

fn validate_hmac_key(key: &str) {
    if key.len() < MIN_HMAC_KEY_HEX_LEN {
        panic!(
            "HMAC_KEY too short: {} chars (min {} hex chars = 256 bits). Generate one with: openssl rand -hex 32",
            key.len(),
            MIN_HMAC_KEY_HEX_LEN
        );
    }
    if !key.chars().all(|c| c.is_ascii_hexdigit()) {
        panic!("HMAC_KEY must be hex-encoded (0-9, a-f, A-F)");
    }
}
