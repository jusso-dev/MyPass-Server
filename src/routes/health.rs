/// Health check endpoint for load balancers and container orchestration.
///
/// Returns a simple JSON response with status and timestamp. Does not check
/// database connectivity — use a dedicated readiness probe for that.
use axum::Json;
use serde_json::{json, Value};

/// GET /health — Returns `{ status: "ok", timestamp: "..." }`.
pub async fn health_check() -> Json<Value> {
    Json(json!({
        "status": "ok",
        "timestamp": chrono::Utc::now().to_rfc3339()
    }))
}
