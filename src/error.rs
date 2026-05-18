/// Unified error type for all API endpoints.
///
/// Each variant maps to a specific HTTP status code and produces a JSON
/// response body of the form `{ "error": "message" }`. Implements `From`
/// conversions for SQLx and anyhow errors so handlers can use `?` freely.
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::json;

#[derive(Debug)]
pub enum AppError {
    /// 404 — Resource not found.
    NotFound(String),
    /// 403 — Owner secret verification failed or access denied.
    Forbidden(String),
    /// 400 — Request validation failed.
    BadRequest(String),
    /// 410 — Resource expired or exhausted (e.g. share link used up).
    Gone(String),
    /// 429 — Rate limit exceeded.
    #[allow(dead_code)]
    RateLimited,
    /// 500 — Unexpected internal error. The inner error is logged but not
    /// exposed to the client.
    Internal(anyhow::Error),
}

impl std::fmt::Display for AppError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AppError::NotFound(msg) => write!(f, "Not found: {msg}"),
            AppError::Forbidden(msg) => write!(f, "Forbidden: {msg}"),
            AppError::BadRequest(msg) => write!(f, "Bad request: {msg}"),
            AppError::Gone(msg) => write!(f, "Gone: {msg}"),
            AppError::RateLimited => write!(f, "Rate limited"),
            AppError::Internal(err) => write!(f, "Internal error: {err}"),
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, message) = match &self {
            AppError::NotFound(msg) => (StatusCode::NOT_FOUND, msg.clone()),
            AppError::Forbidden(msg) => (StatusCode::FORBIDDEN, msg.clone()),
            AppError::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg.clone()),
            AppError::Gone(msg) => (StatusCode::GONE, msg.clone()),
            AppError::RateLimited => (
                StatusCode::TOO_MANY_REQUESTS,
                "Too many requests".to_string(),
            ),
            AppError::Internal(err) => {
                tracing::error!(error = %err, "Internal server error");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Internal server error".to_string(),
                )
            }
        };

        let body = axum::Json(json!({ "error": message }));
        (status, body).into_response()
    }
}

impl From<sqlx::Error> for AppError {
    fn from(err: sqlx::Error) -> Self {
        match err {
            sqlx::Error::RowNotFound => AppError::NotFound("Resource not found".to_string()),
            _ => AppError::Internal(err.into()),
        }
    }
}

impl From<anyhow::Error> for AppError {
    fn from(err: anyhow::Error) -> Self {
        AppError::Internal(err)
    }
}
