/// Share link model — one-time or limited-use links for QR/deep link sharing.
///
/// The link token forms the path of the deep link URL. The actual card decryption
/// key lives in the URL fragment (`#key`) which never reaches the server. This
/// means the server facilitates sharing without ever having access to card data.
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Database row for the `share_links` table.
#[derive(Debug, sqlx::FromRow, Serialize)]
#[allow(dead_code)]
pub struct ShareLink {
    pub id: String,
    pub card_id: String,
    pub token: String,
    pub role: String,
    pub max_uses: i32,
    pub used_count: i32,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

/// Request body for POST /v1/cards/:card_id/links.
#[derive(Debug, Deserialize)]
pub struct CreateShareLinkRequest {
    pub role: Option<String>,
    pub max_uses: Option<i32>,
    pub expires_in_minutes: Option<i64>,
}

/// Response for POST /v1/cards/:card_id/links.
#[derive(Debug, Serialize)]
pub struct CreateShareLinkResponse {
    pub token: String,
    pub expires_at: DateTime<Utc>,
    pub max_uses: i32,
}

/// A single active share link returned in the list endpoint.
#[derive(Debug, Serialize)]
pub struct ShareLinkListItem {
    pub token: String,
    pub role: String,
    pub max_uses: i32,
    pub used_count: i32,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

/// Response for GET /v1/cards/:card_id/links.
#[derive(Debug, Serialize)]
pub struct ShareLinkListResponse {
    pub links: Vec<ShareLinkListItem>,
}

/// Response for GET /v1/links/:token/card — the encrypted blob via share link.
#[derive(Debug, Serialize)]
pub struct RedeemLinkResponse {
    pub card_id: String,
    pub encrypted_blob: String,
    pub blob_iv: String,
    pub blob_auth_tag: String,
    pub version: i32,
    pub schema_version: i32,
    pub child_alias: Option<String>,
    pub role: String,
}
