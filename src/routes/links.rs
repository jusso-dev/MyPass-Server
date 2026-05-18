/// Share link endpoints — QR code and deep link based card sharing.
///
/// Share links allow card owners to generate time-limited, use-limited tokens
/// that form part of a deep link URL. The actual card decryption key lives in
/// the URL fragment (`#key`) which is never sent to the server.
///
/// Flow: Owner creates link → QR code displayed → Scanner opens deep link →
/// App calls GET /v1/links/:token/card → receives encrypted blob → decrypts
/// using key from URL fragment.
use axum::extract::{Path, State};
use axum::response::Response;
use axum::Json;
use chrono::{Duration, Utc};
use rand::Rng;

use crate::cache;
use crate::error::AppError;
use crate::middleware::owner_auth::verify_owner_secret;
use crate::models::share_link::*;
use crate::AppState;

/// Extract and validate the X-Owner-Secret header.
fn get_owner_secret(headers: &axum::http::HeaderMap) -> Result<String, AppError> {
    headers
        .get("X-Owner-Secret")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .ok_or_else(|| AppError::Forbidden("Missing X-Owner-Secret header".into()))
}

/// Verify card ownership.
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

/// Generate a cryptographically random URL-safe token (32 bytes, base64url encoded).
fn generate_token() -> String {
    use base64::Engine;
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill(&mut bytes);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// POST /v1/cards/:card_id/links — Create a share link (owner only).
///
/// Generates a cryptographically random token that forms the path portion
/// of the deep link. The client appends `#base64_card_key` which never
/// reaches the server. Links are time-limited and use-limited.
pub async fn create_share_link(
    State(state): State<AppState>,
    Path(card_id): Path<String>,
    headers: axum::http::HeaderMap,
    Json(body): Json<CreateShareLinkRequest>,
) -> Result<Json<CreateShareLinkResponse>, AppError> {
    let owner_secret = get_owner_secret(&headers)?;
    verify_card_ownership(&state, &card_id, &owner_secret).await?;

    let role = body.role.as_deref().unwrap_or("temporary");
    if !["trusted", "temporary", "readonly", "editor"].contains(&role) {
        return Err(AppError::BadRequest(
            "role must be 'trusted', 'temporary', 'readonly', or 'editor'".into(),
        ));
    }

    let max_uses = body.max_uses.unwrap_or(1);
    if !(1..=10).contains(&max_uses) {
        return Err(AppError::BadRequest("max_uses must be 1-10".into()));
    }

    let expires_in_minutes = body.expires_in_minutes.unwrap_or(1440);
    if !(5..=43200).contains(&expires_in_minutes) {
        return Err(AppError::BadRequest(
            "expires_in_minutes must be 5-43200".into(),
        ));
    }

    let link_id = nanoid::nanoid!();
    let token = generate_token();
    let expires_at = Utc::now() + Duration::minutes(expires_in_minutes);

    sqlx::query(
        "INSERT INTO share_links (id, card_id, token, role, max_uses, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(&link_id)
    .bind(&card_id)
    .bind(&token)
    .bind(role)
    .bind(max_uses)
    .bind(expires_at)
    .execute(&state.db)
    .await?;

    tracing::info!(card_id = %card_id, token = %token, "Share link created");

    Ok(Json(CreateShareLinkResponse {
        token,
        expires_at,
        max_uses,
    }))
}

/// GET /v1/cards/:card_id/links — List active share links for a card (owner only).
///
/// Returns all non-expired share links with used_count < max_uses,
/// ordered by creation time descending.
pub async fn list_share_links(
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
        i32,
        i32,
        chrono::DateTime<Utc>,
        chrono::DateTime<Utc>,
    )> = sqlx::query_as(
        "SELECT token, role, max_uses, used_count, expires_at, created_at
             FROM share_links
             WHERE card_id = $1 AND expires_at > now() AND used_count < max_uses
             ORDER BY created_at DESC",
    )
    .bind(&card_id)
    .fetch_all(&state.db)
    .await?;

    let links: Vec<ShareLinkListItem> = rows
        .into_iter()
        .map(
            |(token, role, max_uses, used_count, expires_at, created_at)| ShareLinkListItem {
                token,
                role,
                max_uses,
                used_count,
                expires_at,
                created_at,
            },
        )
        .collect();

    let response = ShareLinkListResponse { links };
    let etag = cache::compute_etag(&response);

    if let Some(not_modified) = cache::check_not_modified(&headers, &etag) {
        return Ok(not_modified);
    }

    Ok(cache::json_with_etag(response, &etag))
}

/// GET /v1/links/:token/card — Redeem a share link (no auth, rate limited).
///
/// Validates the link hasn't expired or been exhausted, increments `used_count`,
/// and returns the encrypted blob. The client decrypts using the key from the
/// URL fragment. Rate limited aggressively to prevent token brute-forcing.
pub async fn redeem_link(
    State(state): State<AppState>,
    Path(token): Path<String>,
) -> Result<Json<RedeemLinkResponse>, AppError> {
    // Look up the link
    let link = sqlx::query_as::<_, (String, String, String, i32, i32, chrono::DateTime<Utc>)>(
        "SELECT id, card_id, role, max_uses, used_count, expires_at FROM share_links WHERE token = $1"
    )
    .bind(&token)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| AppError::NotFound("Link not found".into()))?;

    let (link_id, card_id, role, max_uses, used_count, expires_at) = link;

    // Check expiry
    if Utc::now() > expires_at {
        return Err(AppError::Gone("Link has expired".into()));
    }

    // Check usage
    if used_count >= max_uses {
        return Err(AppError::Gone(
            "Link has been used the maximum number of times".into(),
        ));
    }

    // Increment used_count
    sqlx::query("UPDATE share_links SET used_count = used_count + 1 WHERE id = $1")
        .bind(&link_id)
        .execute(&state.db)
        .await?;

    // Fetch the card blob
    let card = sqlx::query_as::<_, (String, String, String, i32, i32, Option<String>)>(
        "SELECT encrypted_blob, blob_iv, blob_auth_tag, version, schema_version, child_alias FROM cards WHERE id = $1"
    )
    .bind(&card_id)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| AppError::NotFound("Card not found".into()))?;

    let (encrypted_blob, blob_iv, blob_auth_tag, version, schema_version, child_alias) = card;

    Ok(Json(RedeemLinkResponse {
        card_id,
        encrypted_blob,
        blob_iv,
        blob_auth_tag,
        version,
        schema_version,
        child_alias,
        role,
    }))
}

/// DELETE /v1/cards/:card_id/links/:token — Revoke a share link (owner only).
pub async fn delete_share_link(
    State(state): State<AppState>,
    Path((card_id, token)): Path<(String, String)>,
    headers: axum::http::HeaderMap,
) -> Result<Json<serde_json::Value>, AppError> {
    let owner_secret = get_owner_secret(&headers)?;
    verify_card_ownership(&state, &card_id, &owner_secret).await?;

    let result = sqlx::query("DELETE FROM share_links WHERE card_id = $1 AND token = $2")
        .bind(&card_id)
        .bind(&token)
        .execute(&state.db)
        .await?;

    if result.rows_affected() == 0 {
        return Err(AppError::NotFound("Link not found".into()));
    }

    tracing::info!(card_id = %card_id, token = %token, "Share link revoked");

    Ok(Json(serde_json::json!({ "ok": true })))
}
