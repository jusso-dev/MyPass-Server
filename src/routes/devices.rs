/// Device registration and management endpoints.
///
/// Devices are the only form of identity in MyPass. Each device generates a
/// P-256 keypair in its Secure Enclave on first launch and registers the public
/// key here. The server assigns an opaque nanoid as the device_id.
///
/// There are no user accounts — a device IS the identity.
use axum::extract::{Path, State};
use axum::response::Response;
use axum::Json;

use crate::cache;
use crate::error::AppError;
use crate::models::device::{
    PublicKeyResponse, RegisterDeviceRequest, RegisterDeviceResponse, UpdatePushTokenRequest,
};
use crate::AppState;

const MAX_KEY_LENGTH: usize = 500;
const MAX_TOKEN_LENGTH: usize = 500;

/// POST /v1/devices — Register a new device or return existing one.
///
/// Idempotent: if a device with the given `public_key` already exists,
/// returns the existing device_id and updates `last_seen_at`. This handles
/// app reinstalls where the Secure Enclave key persists.
pub async fn register_device(
    State(state): State<AppState>,
    Json(body): Json<RegisterDeviceRequest>,
) -> Result<Json<RegisterDeviceResponse>, AppError> {
    // Validate input
    if body.public_key.is_empty() || body.public_key.len() > MAX_KEY_LENGTH {
        return Err(AppError::BadRequest("Invalid public_key length".into()));
    }
    if let Some(ref token) = body.push_token {
        if token.len() > MAX_TOKEN_LENGTH {
            return Err(AppError::BadRequest("push_token too long".into()));
        }
    }
    if let Some(ref platform) = body.platform {
        if platform != "ios" && platform != "android" {
            return Err(AppError::BadRequest(
                "platform must be 'ios' or 'android'".into(),
            ));
        }
    }

    // Check for existing device with this public key
    let existing = sqlx::query_scalar::<_, String>("SELECT id FROM devices WHERE public_key = $1")
        .bind(&body.public_key)
        .fetch_optional(&state.db)
        .await?;

    if let Some(device_id) = existing {
        // Update last_seen_at for existing device
        sqlx::query("UPDATE devices SET last_seen_at = now() WHERE id = $1")
            .bind(&device_id)
            .execute(&state.db)
            .await?;

        return Ok(Json(RegisterDeviceResponse { device_id }));
    }

    // Create new device
    let device_id = nanoid::nanoid!();

    sqlx::query(
        "INSERT INTO devices (id, public_key, push_token, platform) VALUES ($1, $2, $3, $4)",
    )
    .bind(&device_id)
    .bind(&body.public_key)
    .bind(&body.push_token)
    .bind(&body.platform)
    .execute(&state.db)
    .await?;

    tracing::info!(device_id = %device_id, "New device registered");

    Ok(Json(RegisterDeviceResponse { device_id }))
}

/// PUT /v1/devices/:device_id/push — Update a device's push notification token.
///
/// Push tokens rotate frequently (especially on iOS). The client calls this
/// whenever it receives a new token from APNs/FCM. No auth required because
/// the device_id is an unguessable nanoid.
pub async fn update_push_token(
    State(state): State<AppState>,
    Path(device_id): Path<String>,
    Json(body): Json<UpdatePushTokenRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    if body.push_token.len() > MAX_TOKEN_LENGTH {
        return Err(AppError::BadRequest("push_token too long".into()));
    }
    if body.platform != "ios" && body.platform != "android" {
        return Err(AppError::BadRequest(
            "platform must be 'ios' or 'android'".into(),
        ));
    }

    let result = sqlx::query(
        "UPDATE devices SET push_token = $1, platform = $2, last_seen_at = now() WHERE id = $3",
    )
    .bind(&body.push_token)
    .bind(&body.platform)
    .bind(&device_id)
    .execute(&state.db)
    .await?;

    if result.rows_affected() == 0 {
        return Err(AppError::NotFound("Device not found".into()));
    }

    Ok(Json(serde_json::json!({ "ok": true })))
}

/// GET /v1/devices/:device_id/public-key — Fetch a device's public key.
///
/// Used during ECDH key agreement: when the card owner wants to share with
/// another device, they need the recipient's public key to wrap the card key.
pub async fn get_public_key(
    State(state): State<AppState>,
    Path(device_id): Path<String>,
    headers: axum::http::HeaderMap,
) -> Result<Response, AppError> {
    let public_key =
        sqlx::query_scalar::<_, String>("SELECT public_key FROM devices WHERE id = $1")
            .bind(&device_id)
            .fetch_optional(&state.db)
            .await?
            .ok_or_else(|| AppError::NotFound("Device not found".into()))?;

    let response = PublicKeyResponse { public_key };
    let etag = cache::compute_etag(&response);

    if let Some(not_modified) = cache::check_not_modified(&headers, &etag) {
        return Ok(not_modified);
    }

    Ok(cache::json_with_etag(response, &etag))
}
