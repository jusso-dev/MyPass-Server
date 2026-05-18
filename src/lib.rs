/// MyPass Server library — exposes the router builder and shared types for
/// integration testing.
use std::sync::Arc;
use std::time::Duration;

use axum::extract::DefaultBodyLimit;
use axum::http::{header, HeaderName, HeaderValue, StatusCode};
use axum::routing::{delete, get, post, put};
use axum::Router;
use sqlx::PgPool;
use tower_governor::{governor::GovernorConfigBuilder, GovernorLayer};
use tower_http::cors::{AllowOrigin, Any, CorsLayer};
use tower_http::set_header::SetResponseHeaderLayer;
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;

pub mod cache;
pub mod config;
pub mod db;
pub mod error;
pub mod middleware;
pub mod models;
pub mod routes;
pub mod services;

use middleware::security_headers as sh;
use services::push::SharedPushService;

/// Request body cap. Cards are at most 64 KiB after encryption (see `MAX_BLOB_LENGTH`
/// in `routes::cards`); we add headroom for JSON envelope overhead.
const MAX_BODY_BYTES: usize = 256 * 1024;

/// Per-request hard timeout. Bounds resource usage under load.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Clone)]
pub struct AppState {
    pub db: PgPool,
    pub config: Arc<config::AppConfig>,
    pub push: SharedPushService,
}

/// Build the Axum router with all routes, middleware, and shared state.
pub fn build_router(state: AppState) -> Router {
    let cors = build_cors(state.config.cors_origin.as_deref());

    // Per-peer-IP token bucket: 10 req/sec sustained, burst of 30. Behind a
    // reverse proxy this rate-limits the proxy IP — fine for portfolio, but a
    // production deploy should swap to `SmartIpKeyExtractor` (X-Forwarded-For).
    let governor_conf = Arc::new(
        GovernorConfigBuilder::default()
            .per_millisecond(100)
            .burst_size(30)
            .finish()
            .expect("rate-limiter config"),
    );

    Router::new()
        .route("/health", get(routes::health::health_check))
        .route("/v1/devices", post(routes::devices::register_device))
        .route(
            "/v1/devices/{device_id}/push",
            put(routes::devices::update_push_token),
        )
        .route(
            "/v1/devices/{device_id}/public-key",
            get(routes::devices::get_public_key),
        )
        .route(
            "/v1/cards",
            post(routes::cards::create_card).get(routes::cards::list_cards),
        )
        .route(
            "/v1/cards/{card_id}",
            get(routes::cards::get_card)
                .put(routes::cards::update_card)
                .delete(routes::cards::delete_card),
        )
        .route(
            "/v1/cards/{card_id}/rotate-key",
            post(routes::cards::rotate_key),
        )
        .route(
            "/v1/cards/{card_id}/subscriptions",
            post(routes::subscriptions::create_subscription)
                .get(routes::subscriptions::list_card_subscriptions),
        )
        .route(
            "/v1/subscriptions/received",
            get(routes::subscriptions::list_received_subscriptions),
        )
        .route(
            "/v1/subscriptions/{subscription_id}",
            delete(routes::subscriptions::delete_subscription),
        )
        .route(
            "/v1/cards/{card_id}/owner-secret",
            put(routes::cards::rotate_owner_secret),
        )
        .route(
            "/v1/cards/{card_id}/links",
            post(routes::links::create_share_link).get(routes::links::list_share_links),
        )
        .route("/v1/links/{token}/card", get(routes::links::redeem_link))
        .route(
            "/v1/cards/{card_id}/links/{token}",
            delete(routes::links::delete_share_link),
        )
        // Cross-cutting middleware. `.layer` wraps the inner service, so the
        // last layer added is the outermost when handling a request.
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .layer(TimeoutLayer::with_status_code(
            StatusCode::GATEWAY_TIMEOUT,
            REQUEST_TIMEOUT,
        ))
        .layer(TraceLayer::new_for_http())
        .layer(cors)
        .layer(GovernorLayer::new(governor_conf))
        .layer(SetResponseHeaderLayer::overriding(
            header::STRICT_TRANSPORT_SECURITY,
            HeaderValue::from_static(sh::HSTS),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            header::X_CONTENT_TYPE_OPTIONS,
            HeaderValue::from_static(sh::CONTENT_TYPE_OPTIONS),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            header::X_FRAME_OPTIONS,
            HeaderValue::from_static(sh::FRAME_OPTIONS),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            header::REFERRER_POLICY,
            HeaderValue::from_static(sh::REFERRER_POLICY),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            HeaderName::from_static("permissions-policy"),
            HeaderValue::from_static(sh::PERMISSIONS_POLICY),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            HeaderName::from_static("cross-origin-opener-policy"),
            HeaderValue::from_static(sh::COOP),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            HeaderName::from_static("cross-origin-resource-policy"),
            HeaderValue::from_static(sh::CORP),
        ))
        .with_state(state)
}

/// Build the CORS layer.
///
/// If `CORS_ORIGIN` is unset the layer is empty — no cross-origin requests are
/// allowed. The previous default of `Any` was unsafe for production deploys.
fn build_cors(origin: Option<&str>) -> CorsLayer {
    match origin {
        Some(o) => CorsLayer::new()
            .allow_origin(
                o.parse::<HeaderValue>()
                    .map(AllowOrigin::exact)
                    .expect("CORS_ORIGIN must be a valid origin string"),
            )
            .allow_methods(Any)
            .allow_headers([
                header::CONTENT_TYPE,
                header::AUTHORIZATION,
                HeaderName::from_static("x-owner-secret"),
                HeaderName::from_static("x-device-id"),
                header::IF_NONE_MATCH,
            ]),
        None => CorsLayer::new(),
    }
}
