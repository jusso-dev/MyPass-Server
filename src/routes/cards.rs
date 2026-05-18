/// Card CRUD endpoints — create, read, update, delete encrypted profile blobs.
///
/// The server treats all card content as opaque ciphertext. It stores Base64-encoded
/// AES-256-GCM encrypted blobs, IVs, and auth tags without ever parsing them.
///
/// Ownership is proved via `X-Owner-Secret` header: the server HMAC-SHA256 hashes
/// the provided secret and constant-time compares it with the stored hash.
/// Read access is also granted to devices with active (non-expired) subscriptions.
use axum::extract::{Path, Query, State};
use axum::response::Response;
use axum::Json;
use chrono::Utc;
use serde::Deserialize;

use crate::cache;
use crate::error::AppError;
use crate::middleware::owner_auth::{hash_owner_secret, verify_owner_secret};
use crate::models::card::*;
use crate::AppState;

const MAX_BLOB_LENGTH: usize = 65536; // 64KB
const MAX_STRING_LENGTH: usize = 500;

/// Extract and validate the X-Owner-Secret header from a request.
fn get_owner_secret(headers: &axum::http::HeaderMap) -> Result<String, AppError> {
    headers
        .get("X-Owner-Secret")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .ok_or_else(|| AppError::Forbidden("Missing X-Owner-Secret header".into()))
}

/// Extract X-Device-Id header from a request.
fn get_device_id(headers: &axum::http::HeaderMap) -> Option<String> {
    headers
        .get("X-Device-Id")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
}

/// Verify that the provided owner secret matches the card's stored hash.
async fn verify_card_ownership(
    state: &AppState,
    card_id: &str,
    owner_secret: &str,
) -> Result<(), AppError> {
    let stored_hash =
        sqlx::query_scalar::<_, String>("SELECT owner_secret_hash FROM cards WHERE id = $1")
            .bind(card_id)
            .fetch_optional(&state.db)
            .await?
            .ok_or_else(|| AppError::NotFound("Card not found".into()))?;

    if !verify_owner_secret(&state.config.hmac_key, owner_secret, &stored_hash) {
        return Err(AppError::Forbidden("Invalid owner secret".into()));
    }
    Ok(())
}

fn validate_base64(s: &str) -> bool {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.decode(s).is_ok()
        || base64::engine::general_purpose::URL_SAFE.decode(s).is_ok()
        || base64::engine::general_purpose::STANDARD_NO_PAD
            .decode(s)
            .is_ok()
}

/// POST /v1/cards — Create a new encrypted card.
///
/// The client generates a random `owner_secret`, encrypts the card with AES-256-GCM,
/// and sends both here. We HMAC the secret for storage and save the encrypted blob.
/// The raw secret goes into the device's Keychain and is never stored server-side.
pub async fn create_card(
    State(state): State<AppState>,
    Json(body): Json<CreateCardRequest>,
) -> Result<Json<CreateCardResponse>, AppError> {
    // Validate
    if body.encrypted_blob.len() > MAX_BLOB_LENGTH {
        return Err(AppError::BadRequest("encrypted_blob too large".into()));
    }
    if body.blob_iv.len() > MAX_STRING_LENGTH || body.blob_auth_tag.len() > MAX_STRING_LENGTH {
        return Err(AppError::BadRequest(
            "blob_iv or blob_auth_tag too long".into(),
        ));
    }
    if body.owner_secret.is_empty() || body.owner_secret.len() > MAX_STRING_LENGTH {
        return Err(AppError::BadRequest("Invalid owner_secret".into()));
    }
    if body.owner_device_id.is_empty() {
        return Err(AppError::BadRequest("owner_device_id required".into()));
    }
    if !validate_base64(&body.encrypted_blob) {
        return Err(AppError::BadRequest(
            "encrypted_blob must be valid Base64".into(),
        ));
    }
    if !validate_base64(&body.blob_iv) {
        return Err(AppError::BadRequest("blob_iv must be valid Base64".into()));
    }
    if !validate_base64(&body.blob_auth_tag) {
        return Err(AppError::BadRequest(
            "blob_auth_tag must be valid Base64".into(),
        ));
    }
    if let Some(ref alias) = body.child_alias {
        if alias.len() > MAX_STRING_LENGTH {
            return Err(AppError::BadRequest("child_alias too long".into()));
        }
    }

    // Verify the device exists
    let device_exists =
        sqlx::query_scalar::<_, bool>("SELECT EXISTS(SELECT 1 FROM devices WHERE id = $1)")
            .bind(&body.owner_device_id)
            .fetch_one(&state.db)
            .await?;
    if !device_exists {
        return Err(AppError::BadRequest("Device not found".into()));
    }

    let card_id = nanoid::nanoid!();
    let owner_secret_hash = hash_owner_secret(&state.config.hmac_key, &body.owner_secret);
    let schema_version = body.schema_version.unwrap_or(1);

    sqlx::query(
        "INSERT INTO cards (id, owner_device_id, owner_secret_hash, encrypted_blob, blob_iv, blob_auth_tag, schema_version, child_alias)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)"
    )
    .bind(&card_id)
    .bind(&body.owner_device_id)
    .bind(&owner_secret_hash)
    .bind(&body.encrypted_blob)
    .bind(&body.blob_iv)
    .bind(&body.blob_auth_tag)
    .bind(schema_version)
    .bind(&body.child_alias)
    .execute(&state.db)
    .await?;

    tracing::info!(card_id = %card_id, "Card created");

    Ok(Json(CreateCardResponse {
        card_id,
        version: 1,
    }))
}

/// GET /v1/cards/:card_id — Fetch the encrypted blob.
///
/// Access is granted if either:
/// 1. The caller provides a valid `X-Owner-Secret` header (owner access), OR
/// 2. The caller provides `X-Device-Id` with an active subscription (subscriber access).
///
/// For subscriber access, `last_fetched_at` and `last_fetched_version` are updated
/// so the owner can see who has viewed the latest version.
pub async fn get_card(
    State(state): State<AppState>,
    Path(card_id): Path<String>,
    headers: axum::http::HeaderMap,
) -> Result<Response, AppError> {
    // Try owner access first
    let owner_secret = get_owner_secret(&headers).ok();
    let device_id = get_device_id(&headers);

    let card = sqlx::query_as::<_, (String, String, String, String, String, i32, i32, chrono::DateTime<Utc>)>(
        "SELECT id, owner_secret_hash, encrypted_blob, blob_iv, blob_auth_tag, version, schema_version, updated_at FROM cards WHERE id = $1"
    )
    .bind(&card_id)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| AppError::NotFound("Card not found".into()))?;

    let (
        id,
        owner_secret_hash,
        encrypted_blob,
        blob_iv,
        blob_auth_tag,
        version,
        schema_version,
        updated_at,
    ) = card;

    let mut authorized = false;
    let mut is_subscriber = false;

    // Check owner access
    if let Some(ref secret) = owner_secret {
        if verify_owner_secret(&state.config.hmac_key, secret, &owner_secret_hash) {
            authorized = true;
        }
    }

    // Check subscriber access
    if !authorized {
        if let Some(ref dev_id) = device_id {
            let has_sub = sqlx::query_scalar::<_, bool>(
                "SELECT EXISTS(SELECT 1 FROM card_subscriptions WHERE card_id = $1 AND device_id = $2 AND (expires_at IS NULL OR expires_at > now()))"
            )
            .bind(&card_id)
            .bind(dev_id)
            .fetch_one(&state.db)
            .await?;

            if has_sub {
                authorized = true;
                is_subscriber = true;
            }
        }
    }

    if !authorized {
        return Err(AppError::Forbidden("Access denied".into()));
    }

    // ETag based on card version — cheap and changes on every update
    let etag = cache::version_etag(version);

    // Return 304 if client already has this version
    if let Some(not_modified) = cache::check_not_modified(&headers, &etag) {
        return Ok(not_modified);
    }

    // Only update subscriber fetch tracking when actually returning data
    if is_subscriber {
        if let Some(ref dev_id) = device_id {
            sqlx::query(
                "UPDATE card_subscriptions SET last_fetched_at = now(), last_fetched_version = $1 WHERE card_id = $2 AND device_id = $3"
            )
            .bind(version)
            .bind(&card_id)
            .bind(dev_id)
            .execute(&state.db)
            .await?;
        }
    }

    Ok(cache::json_with_etag(
        CardBlobResponse {
            card_id: id,
            encrypted_blob,
            blob_iv,
            blob_auth_tag,
            version,
            schema_version,
            updated_at,
        },
        &etag,
    ))
}

/// PUT /v1/cards/:card_id — Update the encrypted blob (owner only).
///
/// After updating, sends silent push notifications to all active subscribers
/// so they know a new version is available. The push payload contains only
/// the card_id and version — no card content.
pub async fn update_card(
    State(state): State<AppState>,
    Path(card_id): Path<String>,
    headers: axum::http::HeaderMap,
    Json(body): Json<UpdateCardRequest>,
) -> Result<Json<UpdateCardResponse>, AppError> {
    let owner_secret = get_owner_secret(&headers)?;
    verify_card_ownership(&state, &card_id, &owner_secret).await?;

    // Validate
    if body.encrypted_blob.len() > MAX_BLOB_LENGTH {
        return Err(AppError::BadRequest("encrypted_blob too large".into()));
    }
    if body.blob_iv.len() > MAX_STRING_LENGTH || body.blob_auth_tag.len() > MAX_STRING_LENGTH {
        return Err(AppError::BadRequest(
            "blob_iv or blob_auth_tag too long".into(),
        ));
    }
    if !validate_base64(&body.encrypted_blob) {
        return Err(AppError::BadRequest(
            "encrypted_blob must be valid Base64".into(),
        ));
    }
    if !validate_base64(&body.blob_iv) {
        return Err(AppError::BadRequest("blob_iv must be valid Base64".into()));
    }
    if !validate_base64(&body.blob_auth_tag) {
        return Err(AppError::BadRequest(
            "blob_auth_tag must be valid Base64".into(),
        ));
    }

    // Update card and bump version
    let new_version = sqlx::query_scalar::<_, i32>(
        "UPDATE cards SET encrypted_blob = $1, blob_iv = $2, blob_auth_tag = $3, schema_version = COALESCE($4, schema_version), child_alias = COALESCE($5, child_alias), version = version + 1, updated_at = now() WHERE id = $6 RETURNING version"
    )
    .bind(&body.encrypted_blob)
    .bind(&body.blob_iv)
    .bind(&body.blob_auth_tag)
    .bind(body.schema_version)
    .bind(&body.child_alias)
    .bind(&card_id)
    .fetch_one(&state.db)
    .await?;

    // Notify subscribers via push
    let subscribers: Vec<(String, Option<String>)> = sqlx::query_as(
        "SELECT cs.device_id, d.push_token FROM card_subscriptions cs JOIN devices d ON d.id = cs.device_id WHERE cs.card_id = $1 AND (cs.expires_at IS NULL OR cs.expires_at > now())"
    )
    .bind(&card_id)
    .fetch_all(&state.db)
    .await?;

    let mut notified = 0i32;
    for (_device_id, push_token) in &subscribers {
        if let Some(token) = push_token {
            if state
                .push
                .notify_card_update(token, &card_id, new_version)
                .await
                .is_ok()
            {
                notified += 1;
            }
        }
    }

    tracing::info!(card_id = %card_id, version = new_version, notified, "Card updated");

    Ok(Json(UpdateCardResponse {
        card_id,
        version: new_version,
        subscribers_notified: notified,
    }))
}

/// DELETE /v1/cards/:card_id — Delete a card and cascade-delete all subscriptions and links.
///
/// Owner-only. The CASCADE foreign keys handle cleanup of subscriptions and share links.
pub async fn delete_card(
    State(state): State<AppState>,
    Path(card_id): Path<String>,
    headers: axum::http::HeaderMap,
) -> Result<Json<serde_json::Value>, AppError> {
    let owner_secret = get_owner_secret(&headers)?;
    verify_card_ownership(&state, &card_id, &owner_secret).await?;

    // Notify subscribers before deleting (CASCADE will remove subscriptions)
    let subscribers: Vec<(String, Option<String>)> = sqlx::query_as(
        "SELECT cs.device_id, d.push_token FROM card_subscriptions cs JOIN devices d ON d.id = cs.device_id WHERE cs.card_id = $1 AND (cs.expires_at IS NULL OR cs.expires_at > now())"
    )
    .bind(&card_id)
    .fetch_all(&state.db)
    .await?;

    sqlx::query("DELETE FROM cards WHERE id = $1")
        .bind(&card_id)
        .execute(&state.db)
        .await?;

    // Send push notifications after successful deletion
    let mut notified = 0i32;
    for (_device_id, push_token) in &subscribers {
        if let Some(token) = push_token {
            if state
                .push
                .notify_card_deleted(token, &card_id)
                .await
                .is_ok()
            {
                notified += 1;
            }
        }
    }

    tracing::info!(card_id = %card_id, notified, "Card deleted");

    Ok(Json(serde_json::json!({ "ok": true })))
}

/// Query parameters for GET /v1/cards.
#[derive(Debug, Deserialize)]
pub struct ListCardsQuery {
    pub owner_device_id: Option<String>,
}

/// GET /v1/cards — List cards owned by a device (metadata only, no blobs).
///
/// Filtered by the `X-Device-Id` header. Returns only card metadata including
/// subscriber count — no encrypted content. The device_id is an unguessable
/// nanoid so no additional auth is needed for listing.
pub async fn list_cards(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Query(query): Query<ListCardsQuery>,
) -> Result<Response, AppError> {
    let device_id = query
        .owner_device_id
        .or_else(|| get_device_id(&headers))
        .ok_or_else(|| AppError::BadRequest("owner_device_id or X-Device-Id required".into()))?;

    #[allow(clippy::type_complexity)]
    let rows: Vec<(String, Option<String>, i32, i32, i64, chrono::DateTime<Utc>, chrono::DateTime<Utc>)> = sqlx::query_as(
        "SELECT c.id, c.child_alias, c.version, c.schema_version,
                (SELECT COUNT(*) FROM card_subscriptions cs WHERE cs.card_id = c.id AND (cs.expires_at IS NULL OR cs.expires_at > now())),
                c.created_at, c.updated_at
         FROM cards c WHERE c.owner_device_id = $1
         ORDER BY c.created_at DESC"
    )
    .bind(&device_id)
    .fetch_all(&state.db)
    .await?;

    let cards: Vec<CardListItem> = rows
        .into_iter()
        .map(
            |(
                card_id,
                child_alias,
                version,
                schema_version,
                subscriber_count,
                created_at,
                updated_at,
            )| {
                CardListItem {
                    card_id,
                    child_alias,
                    version,
                    schema_version,
                    subscriber_count,
                    created_at,
                    updated_at,
                }
            },
        )
        .collect();

    let response = CardListResponse { cards };
    let etag = cache::compute_etag(&response);

    if let Some(not_modified) = cache::check_not_modified(&headers, &etag) {
        return Ok(not_modified);
    }

    Ok(cache::json_with_etag(response, &etag))
}

/// PUT /v1/cards/:card_id/owner-secret — Rotate the owner secret for a card.
///
/// The caller provides the current owner secret in `X-Owner-Secret` and a new
/// secret in the request body. The server verifies the old secret, HMAC-hashes
/// the new one, and updates the stored hash.
pub async fn rotate_owner_secret(
    State(state): State<AppState>,
    Path(card_id): Path<String>,
    headers: axum::http::HeaderMap,
    Json(body): Json<RotateOwnerSecretRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let owner_secret = get_owner_secret(&headers)?;
    verify_card_ownership(&state, &card_id, &owner_secret).await?;

    // Validate the new secret
    if body.new_owner_secret.is_empty() || body.new_owner_secret.len() > MAX_STRING_LENGTH {
        return Err(AppError::BadRequest("Invalid new_owner_secret".into()));
    }

    let new_hash = hash_owner_secret(&state.config.hmac_key, &body.new_owner_secret);

    sqlx::query("UPDATE cards SET owner_secret_hash = $1 WHERE id = $2")
        .bind(&new_hash)
        .bind(&card_id)
        .execute(&state.db)
        .await?;

    tracing::info!(card_id = %card_id, "Owner secret rotated");

    Ok(Json(serde_json::json!({ "ok": true })))
}

/// POST /v1/cards/:card_id/rotate-key — Atomically rotate the card encryption key.
///
/// Used after revoking a subscriber: the owner re-encrypts the card with a new
/// AES key and provides new wrapped keys for all remaining subscribers. This is
/// done in a single database transaction to ensure atomicity.
///
/// Subscribers not listed in `subscriber_keys` retain their old wrapped key,
/// which cannot decrypt the new blob — effectively revoking their access.
pub async fn rotate_key(
    State(state): State<AppState>,
    Path(card_id): Path<String>,
    headers: axum::http::HeaderMap,
    Json(body): Json<RotateKeyRequest>,
) -> Result<Json<RotateKeyResponse>, AppError> {
    let owner_secret = get_owner_secret(&headers)?;
    verify_card_ownership(&state, &card_id, &owner_secret).await?;

    // Validate
    if body.encrypted_blob.len() > MAX_BLOB_LENGTH {
        return Err(AppError::BadRequest("encrypted_blob too large".into()));
    }
    if !validate_base64(&body.encrypted_blob) {
        return Err(AppError::BadRequest(
            "encrypted_blob must be valid Base64".into(),
        ));
    }
    if !validate_base64(&body.blob_iv) {
        return Err(AppError::BadRequest("blob_iv must be valid Base64".into()));
    }
    if !validate_base64(&body.blob_auth_tag) {
        return Err(AppError::BadRequest(
            "blob_auth_tag must be valid Base64".into(),
        ));
    }

    // Execute in a transaction for atomicity
    let mut tx = state.db.begin().await?;

    let new_version = sqlx::query_scalar::<_, i32>(
        "UPDATE cards SET encrypted_blob = $1, blob_iv = $2, blob_auth_tag = $3, version = version + 1, updated_at = now() WHERE id = $4 RETURNING version"
    )
    .bind(&body.encrypted_blob)
    .bind(&body.blob_iv)
    .bind(&body.blob_auth_tag)
    .bind(&card_id)
    .fetch_one(&mut *tx)
    .await?;

    // Update wrapped keys for listed subscribers
    for sub_key in &body.subscriber_keys {
        sqlx::query(
            "UPDATE card_subscriptions SET wrapped_key = $1, ephemeral_public_key = $2 WHERE card_id = $3 AND device_id = $4"
        )
        .bind(&sub_key.wrapped_key)
        .bind(&sub_key.ephemeral_public_key)
        .bind(&card_id)
        .bind(&sub_key.device_id)
        .execute(&mut *tx)
        .await?;
    }

    tx.commit().await?;

    tracing::info!(card_id = %card_id, version = new_version, "Card key rotated");

    Ok(Json(RotateKeyResponse {
        card_id,
        version: new_version,
        rotated: true,
    }))
}
