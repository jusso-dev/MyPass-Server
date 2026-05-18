/// Subscription model — represents a device's access grant to an encrypted card.
///
/// When a card owner shares with another device, they perform ECDH key agreement
/// using the recipient's public key and wrap the card's AES key. The wrapped key
/// and ephemeral public key are stored here so the recipient can unwrap and decrypt.
/// The server never sees the plaintext card key.
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Database row for the `card_subscriptions` table.
#[derive(Debug, sqlx::FromRow, Serialize)]
#[allow(dead_code)]
pub struct Subscription {
    pub id: String,
    pub card_id: String,
    pub device_id: String,
    pub wrapped_key: String,
    pub ephemeral_public_key: String,
    pub role: String,
    pub expires_at: Option<DateTime<Utc>>,
    pub last_fetched_at: Option<DateTime<Utc>>,
    pub last_fetched_version: Option<i32>,
    pub created_at: DateTime<Utc>,
}

/// Request body for POST /v1/cards/:card_id/subscriptions.
#[derive(Debug, Deserialize)]
pub struct CreateSubscriptionRequest {
    pub device_id: String,
    pub wrapped_key: String,
    pub ephemeral_public_key: String,
    pub role: Option<String>,
    pub expires_at: Option<DateTime<Utc>>,
    /// ECDH-wrapped owner secret (required for editor role).
    pub wrapped_owner_secret: Option<String>,
    pub owner_secret_ephemeral_key: Option<String>,
}

/// Response for POST /v1/cards/:card_id/subscriptions.
#[derive(Debug, Serialize)]
pub struct CreateSubscriptionResponse {
    pub subscription_id: String,
    pub card_id: String,
    pub device_id: String,
    pub role: String,
    pub expires_at: Option<DateTime<Utc>>,
}

/// A single subscription in the received-subscriptions list.
#[derive(Debug, Serialize)]
pub struct ReceivedSubscription {
    pub subscription_id: String,
    pub card_id: String,
    pub child_alias: Option<String>,
    pub role: String,
    pub expires_at: Option<DateTime<Utc>>,
    pub wrapped_key: String,
    pub ephemeral_public_key: String,
    pub wrapped_owner_secret: Option<String>,
    pub owner_secret_ephemeral_key: Option<String>,
    pub card_version: i32,
    pub last_fetched_version: Option<i32>,
    pub is_stale: bool,
}

/// Response for GET /v1/subscriptions/received.
#[derive(Debug, Serialize)]
pub struct ReceivedSubscriptionsResponse {
    pub subscriptions: Vec<ReceivedSubscription>,
}

/// Owner view of a subscriber.
#[derive(Debug, Serialize)]
pub struct SubscriberInfo {
    pub subscription_id: String,
    pub device_id: String,
    pub role: String,
    pub expires_at: Option<DateTime<Utc>>,
    pub last_fetched_at: Option<DateTime<Utc>>,
    pub last_fetched_version: Option<i32>,
    pub created_at: DateTime<Utc>,
}

/// Response for GET /v1/cards/:card_id/subscriptions (owner view).
#[derive(Debug, Serialize)]
pub struct SubscribersListResponse {
    pub subscriptions: Vec<SubscriberInfo>,
}
