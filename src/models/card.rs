/// Card model — an encrypted profile blob that the server stores but cannot read.
///
/// All card content (behavioural traits, calming strategies, etc.) is encrypted
/// client-side with AES-256-GCM. The server only stores the ciphertext, IV,
/// and auth tag as opaque Base64 strings. Ownership is proved via HMAC-SHA256
/// of a client-generated secret — no accounts, no JWT.
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Database row for the `cards` table.
#[derive(Debug, sqlx::FromRow, Serialize)]
#[allow(dead_code)]
pub struct Card {
    pub id: String,
    pub owner_device_id: String,
    pub owner_secret_hash: String,
    pub encrypted_blob: String,
    pub blob_iv: String,
    pub blob_auth_tag: String,
    pub schema_version: i32,
    pub version: i32,
    pub child_alias: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Request body for POST /v1/cards.
#[derive(Debug, Deserialize)]
pub struct CreateCardRequest {
    pub owner_device_id: String,
    pub owner_secret: String,
    pub encrypted_blob: String,
    pub blob_iv: String,
    pub blob_auth_tag: String,
    pub schema_version: Option<i32>,
    pub child_alias: Option<String>,
}

/// Response for POST /v1/cards.
#[derive(Debug, Serialize)]
pub struct CreateCardResponse {
    pub card_id: String,
    pub version: i32,
}

/// Response for GET /v1/cards/:card_id — the encrypted blob payload.
#[derive(Debug, Serialize)]
pub struct CardBlobResponse {
    pub card_id: String,
    pub encrypted_blob: String,
    pub blob_iv: String,
    pub blob_auth_tag: String,
    pub version: i32,
    pub schema_version: i32,
    pub updated_at: DateTime<Utc>,
}

/// Request body for PUT /v1/cards/:card_id.
#[derive(Debug, Deserialize)]
pub struct UpdateCardRequest {
    pub encrypted_blob: String,
    pub blob_iv: String,
    pub blob_auth_tag: String,
    pub schema_version: Option<i32>,
    pub child_alias: Option<String>,
}

/// Response for PUT /v1/cards/:card_id.
#[derive(Debug, Serialize)]
pub struct UpdateCardResponse {
    pub card_id: String,
    pub version: i32,
    pub subscribers_notified: i32,
}

/// Card metadata returned in the list endpoint (no blob data).
#[derive(Debug, Serialize)]
pub struct CardListItem {
    pub card_id: String,
    pub child_alias: Option<String>,
    pub version: i32,
    pub schema_version: i32,
    pub subscriber_count: i64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Response for GET /v1/cards?owner_device_id=...
#[derive(Debug, Serialize)]
pub struct CardListResponse {
    pub cards: Vec<CardListItem>,
}

/// Request body for POST /v1/cards/:card_id/rotate-key.
#[derive(Debug, Deserialize)]
pub struct RotateKeyRequest {
    pub encrypted_blob: String,
    pub blob_iv: String,
    pub blob_auth_tag: String,
    pub subscriber_keys: Vec<SubscriberKeyUpdate>,
}

/// A single subscriber's new wrapped key during key rotation.
#[derive(Debug, Deserialize)]
pub struct SubscriberKeyUpdate {
    pub device_id: String,
    pub wrapped_key: String,
    pub ephemeral_public_key: String,
}

/// Response for POST /v1/cards/:card_id/rotate-key.
#[derive(Debug, Serialize)]
pub struct RotateKeyResponse {
    pub card_id: String,
    pub version: i32,
    pub rotated: bool,
}

/// Request body for PUT /v1/cards/:card_id/owner-secret.
#[derive(Debug, Deserialize)]
pub struct RotateOwnerSecretRequest {
    pub new_owner_secret: String,
}
