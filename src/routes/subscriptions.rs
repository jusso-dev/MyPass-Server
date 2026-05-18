/// Subscription endpoints — manage shared access to encrypted cards.
///
/// When a card owner shares with another device, the client performs ECDH key
/// agreement to wrap the card's AES key with the recipient's public key. The
/// wrapped key is stored here so the recipient can fetch and unwrap it using
/// their Secure Enclave private key. The server never sees the plaintext card key.
use axum::extract::{Path, State};
use axum::response::Response;
use axum::Json;
use chrono::Utc;

use crate::cache;
use crate::error::AppError;
use crate::middleware::owner_auth::verify_owner_secret;
use crate::models::subscription::*;
use crate::AppState;

const MAX_STRING_LENGTH: usize = 500;

/// Extract and validate the X-Owner-Secret header.
fn get_owner_secret(headers: &axum::http::HeaderMap) -> Result<String, AppError> {
    headers
        .get("X-Owner-Secret")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .ok_or_else(|| AppError::Forbidden("Missing X-Owner-Secret header".into()))
}

/// Extract X-Device-Id header.
fn get_device_id(headers: &axum::http::HeaderMap) -> Result<String, AppError> {
    headers
        .get("X-Device-Id")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .ok_or_else(|| AppError::BadRequest("Missing X-Device-Id header".into()))
}

/// Verify card ownership by checking the owner secret against the stored hash.
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

/// POST /v1/cards/:card_id/subscriptions — Grant a device access to a card.
///
/// Owner-only. The owner's client wraps the card key with the recipient's public
/// key and uploads the wrapped key here. Upserts: if the device already has a
/// subscription, updates the wrapped key and role.
///
/// Sends a push notification to the recipient device.
pub async fn create_subscription(
    State(state): State<AppState>,
    Path(card_id): Path<String>,
    headers: axum::http::HeaderMap,
    Json(body): Json<CreateSubscriptionRequest>,
) -> Result<Json<CreateSubscriptionResponse>, AppError> {
    let owner_secret = get_owner_secret(&headers)?;
    verify_card_ownership(&state, &card_id, &owner_secret).await?;

    // Validate
    if body.device_id.is_empty() || body.device_id.len() > MAX_STRING_LENGTH {
        return Err(AppError::BadRequest("Invalid device_id".into()));
    }
    if body.wrapped_key.is_empty() || body.wrapped_key.len() > MAX_STRING_LENGTH {
        return Err(AppError::BadRequest("Invalid wrapped_key".into()));
    }
    if body.ephemeral_public_key.is_empty() || body.ephemeral_public_key.len() > MAX_STRING_LENGTH {
        return Err(AppError::BadRequest("Invalid ephemeral_public_key".into()));
    }

    let role = body.role.as_deref().unwrap_or("trusted");
    if !["trusted", "temporary", "readonly", "editor"].contains(&role) {
        return Err(AppError::BadRequest(
            "role must be 'trusted', 'temporary', 'readonly', or 'editor'".into(),
        ));
    }

    // Editor role requires a wrapped owner secret
    if role == "editor"
        && (body.wrapped_owner_secret.is_none() || body.owner_secret_ephemeral_key.is_none())
    {
        return Err(AppError::BadRequest(
            "editor role requires wrapped_owner_secret and owner_secret_ephemeral_key".into(),
        ));
    }

    // Prevent sharing with yourself
    let owner_device_id =
        sqlx::query_scalar::<_, String>("SELECT owner_device_id FROM cards WHERE id = $1")
            .bind(&card_id)
            .fetch_one(&state.db)
            .await?;
    if body.device_id == owner_device_id {
        return Err(AppError::BadRequest(
            "Cannot share a card with your own device".into(),
        ));
    }

    // Verify the target device exists
    let device_exists =
        sqlx::query_scalar::<_, bool>("SELECT EXISTS(SELECT 1 FROM devices WHERE id = $1)")
            .bind(&body.device_id)
            .fetch_one(&state.db)
            .await?;
    if !device_exists {
        return Err(AppError::BadRequest("Target device not found".into()));
    }

    let subscription_id = nanoid::nanoid!();

    // Upsert: insert or update on conflict
    sqlx::query(
        "INSERT INTO card_subscriptions (id, card_id, device_id, wrapped_key, ephemeral_public_key, role, expires_at, wrapped_owner_secret, owner_secret_ephemeral_key)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
         ON CONFLICT (card_id, device_id) DO UPDATE SET wrapped_key = $4, ephemeral_public_key = $5, role = $6, expires_at = $7, wrapped_owner_secret = $8, owner_secret_ephemeral_key = $9"
    )
    .bind(&subscription_id)
    .bind(&card_id)
    .bind(&body.device_id)
    .bind(&body.wrapped_key)
    .bind(&body.ephemeral_public_key)
    .bind(role)
    .bind(body.expires_at)
    .bind(&body.wrapped_owner_secret)
    .bind(&body.owner_secret_ephemeral_key)
    .execute(&state.db)
    .await?;

    // Send push notification to recipient
    let push_token: Option<String> =
        sqlx::query_scalar("SELECT push_token FROM devices WHERE id = $1")
            .bind(&body.device_id)
            .fetch_optional(&state.db)
            .await?
            .flatten();

    if let Some(token) = push_token {
        let _ = state.push.notify_new_share(&token, &card_id).await;
    }

    tracing::info!(card_id = %card_id, device_id = %body.device_id, "Subscription created");

    Ok(Json(CreateSubscriptionResponse {
        subscription_id,
        card_id,
        device_id: body.device_id,
        role: role.to_string(),
        expires_at: body.expires_at,
    }))
}

/// GET /v1/subscriptions/received — List all cards shared with a device.
///
/// Returns active (non-expired) subscriptions including the wrapped key and
/// ephemeral public key needed for ECDH unwrapping. The `is_stale` flag
/// indicates whether the subscriber has fetched the latest card version.
pub async fn list_received_subscriptions(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Result<Response, AppError> {
    let device_id = get_device_id(&headers)?;

    #[allow(clippy::type_complexity)]
    let rows: Vec<(String, String, Option<String>, String, Option<chrono::DateTime<Utc>>, String, String, Option<String>, Option<String>, i32, Option<i32>)> = sqlx::query_as(
        "SELECT cs.id, cs.card_id, c.child_alias, cs.role, cs.expires_at, cs.wrapped_key, cs.ephemeral_public_key, cs.wrapped_owner_secret, cs.owner_secret_ephemeral_key, c.version, cs.last_fetched_version
         FROM card_subscriptions cs
         JOIN cards c ON c.id = cs.card_id
         WHERE cs.device_id = $1 AND (cs.expires_at IS NULL OR cs.expires_at > now())
         ORDER BY cs.created_at DESC"
    )
    .bind(&device_id)
    .fetch_all(&state.db)
    .await?;

    let subscriptions: Vec<ReceivedSubscription> = rows
        .into_iter()
        .map(
            |(
                subscription_id,
                card_id,
                child_alias,
                role,
                expires_at,
                wrapped_key,
                ephemeral_public_key,
                wrapped_owner_secret,
                owner_secret_ephemeral_key,
                card_version,
                last_fetched_version,
            )| {
                let is_stale = last_fetched_version.is_none_or(|v| v < card_version);
                ReceivedSubscription {
                    subscription_id,
                    card_id,
                    child_alias,
                    role,
                    expires_at,
                    wrapped_key,
                    ephemeral_public_key,
                    wrapped_owner_secret,
                    owner_secret_ephemeral_key,
                    card_version,
                    last_fetched_version,
                    is_stale,
                }
            },
        )
        .collect();

    let response = ReceivedSubscriptionsResponse { subscriptions };
    let etag = cache::compute_etag(&response);

    if let Some(not_modified) = cache::check_not_modified(&headers, &etag) {
        return Ok(not_modified);
    }

    Ok(cache::json_with_etag(response, &etag))
}

/// GET /v1/cards/:card_id/subscriptions — List all subscribers for a card (owner view).
///
/// Owner-only. Shows subscription metadata including when each subscriber
/// last fetched the card, useful for the owner to see who's up to date.
pub async fn list_card_subscriptions(
    State(state): State<AppState>,
    Path(card_id): Path<String>,
    headers: axum::http::HeaderMap,
) -> Result<Response, AppError> {
    let owner_secret = get_owner_secret(&headers)?;
    verify_card_ownership(&state, &card_id, &owner_secret).await?;

    #[allow(clippy::type_complexity)]
    let rows: Vec<(
        String,
        String,
        String,
        Option<chrono::DateTime<Utc>>,
        Option<chrono::DateTime<Utc>>,
        Option<i32>,
        chrono::DateTime<Utc>,
    )> = sqlx::query_as(
        "SELECT id, device_id, role, expires_at, last_fetched_at, last_fetched_version, created_at
         FROM card_subscriptions WHERE card_id = $1 ORDER BY created_at DESC",
    )
    .bind(&card_id)
    .fetch_all(&state.db)
    .await?;

    let subscriptions: Vec<SubscriberInfo> = rows
        .into_iter()
        .map(
            |(
                subscription_id,
                device_id,
                role,
                expires_at,
                last_fetched_at,
                last_fetched_version,
                created_at,
            )| {
                SubscriberInfo {
                    subscription_id,
                    device_id,
                    role,
                    expires_at,
                    last_fetched_at,
                    last_fetched_version,
                    created_at,
                }
            },
        )
        .collect();

    let response = SubscribersListResponse { subscriptions };
    let etag = cache::compute_etag(&response);

    if let Some(not_modified) = cache::check_not_modified(&headers, &etag) {
        return Ok(not_modified);
    }

    Ok(cache::json_with_etag(response, &etag))
}

/// DELETE /v1/subscriptions/:subscription_id — Revoke a subscription (owner only).
///
/// Looks up the subscription, finds the parent card, verifies ownership,
/// then deletes. After revocation, the owner should call rotate-key to
/// re-encrypt the card so the revoked device can't decrypt future versions.
pub async fn delete_subscription(
    State(state): State<AppState>,
    Path(subscription_id): Path<String>,
    headers: axum::http::HeaderMap,
) -> Result<Json<serde_json::Value>, AppError> {
    let owner_secret = get_owner_secret(&headers)?;

    // Look up subscription to find the card
    let card_id =
        sqlx::query_scalar::<_, String>("SELECT card_id FROM card_subscriptions WHERE id = $1")
            .bind(&subscription_id)
            .fetch_optional(&state.db)
            .await?
            .ok_or_else(|| AppError::NotFound("Subscription not found".into()))?;

    verify_card_ownership(&state, &card_id, &owner_secret).await?;

    sqlx::query("DELETE FROM card_subscriptions WHERE id = $1")
        .bind(&subscription_id)
        .execute(&state.db)
        .await?;

    tracing::info!(subscription_id = %subscription_id, "Subscription revoked");

    Ok(Json(serde_json::json!({ "ok": true })))
}
