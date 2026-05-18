/// HTTP caching helpers — ETag generation and conditional request handling.
///
/// GET endpoints use ETags to let clients skip re-downloading unchanged data.
/// The server computes an ETag from the response payload (either a version number
/// or a SHA-256 hash of the serialized JSON) and checks `If-None-Match` to return
/// 304 Not Modified when the client already has the latest data.
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::Serialize;
use sha2::{Digest, Sha256};

/// Compute a quoted ETag by hashing the JSON-serialized response data.
/// Uses the first 16 bytes of SHA-256 for a compact but collision-resistant tag.
pub fn compute_etag(data: &impl Serialize) -> String {
    let json = serde_json::to_string(data).unwrap_or_default();
    let hash = Sha256::digest(json.as_bytes());
    format!("\"{}\"", hex::encode(&hash[..16]))
}

/// Build an ETag from a simple version number (cheaper than hashing).
pub fn version_etag(version: i32) -> String {
    format!("\"v{version}\"")
}

/// Check the `If-None-Match` request header against the computed ETag.
/// Returns `Some(304 response)` if the client's cached version is still valid.
pub fn check_not_modified(headers: &HeaderMap, etag: &str) -> Option<Response> {
    let if_none_match = headers.get("If-None-Match")?;
    let value = if_none_match.to_str().ok()?;
    if value == etag {
        let mut response = StatusCode::NOT_MODIFIED.into_response();
        response
            .headers_mut()
            .insert("ETag", HeaderValue::from_str(etag).unwrap());
        Some(response)
    } else {
        None
    }
}

/// Wrap a serializable value as a JSON response with an ETag header.
pub fn json_with_etag(data: impl Serialize, etag: &str) -> Response {
    let mut response = axum::Json(data).into_response();
    if let Ok(val) = HeaderValue::from_str(etag) {
        response.headers_mut().insert("ETag", val);
    }
    response
}
