/// Device model — represents a registered device identified by its public key.
///
/// Devices have no associated user account. Identity is purely the P-256
/// keypair generated in the device's Secure Enclave / Android Keystore.
/// The `id` is a server-generated nanoid, opaque and unguessable.
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Database row for the `devices` table.
#[derive(Debug, sqlx::FromRow, Serialize)]
#[allow(dead_code)]
pub struct Device {
    pub id: String,
    pub public_key: String,
    pub push_token: Option<String>,
    pub platform: Option<String>,
    pub registered_at: DateTime<Utc>,
    pub last_seen_at: DateTime<Utc>,
}

/// Request body for POST /v1/devices.
#[derive(Debug, Deserialize)]
pub struct RegisterDeviceRequest {
    pub public_key: String,
    pub push_token: Option<String>,
    pub platform: Option<String>,
}

/// Response for POST /v1/devices.
#[derive(Debug, Serialize)]
pub struct RegisterDeviceResponse {
    pub device_id: String,
}

/// Request body for PUT /v1/devices/:device_id/push.
#[derive(Debug, Deserialize)]
pub struct UpdatePushTokenRequest {
    pub push_token: String,
    pub platform: String,
}

/// Response for GET /v1/devices/:device_id/public-key.
#[derive(Debug, Serialize)]
pub struct PublicKeyResponse {
    pub public_key: String,
}
