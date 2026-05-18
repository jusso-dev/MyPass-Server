/// MyPass Server — Zero-knowledge encrypted card relay.
///
/// This server is a "dumb blob relay" for the MyPass autism awareness card-sharing
/// platform. It stores encrypted profile cards, wrapped encryption keys, and push
/// tokens. All encryption/decryption happens on-device; the server never sees
/// plaintext card data.
///
/// No user accounts. No PII. No JWT. Identity is a device keypair.
/// Ownership is proved by HMAC-SHA256 of a client-generated secret.
use std::net::SocketAddr;
use std::sync::Arc;

use sqlx::PgPool;

use mypass_server::config::AppConfig;
use mypass_server::db;
use mypass_server::services::push::PushService;
use mypass_server::{build_router, AppState};

#[tokio::main]
async fn main() {
    // Load .env file if present (development)
    let _ = dotenvy::dotenv();

    // Initialize structured logging
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "mypass_server=info,tower_http=info".into()),
        )
        .json()
        .init();

    let config = AppConfig::from_env();
    let port = config.port;

    // Set up database
    let pool = db::create_pool(&config.database_url).await;
    db::run_migrations(&pool).await;
    tracing::info!("Database connected and migrations applied");

    // Set up push service
    let push = Arc::new(PushService::new(
        config.fcm_project_id.clone(),
        config.fcm_client_email.clone(),
        config.fcm_private_key.clone(),
    ));

    let state = AppState {
        db: pool.clone(),
        config: Arc::new(config),
        push,
    };

    // Spawn background cleanup task for expired links and subscriptions
    spawn_cleanup_task(pool.clone(), state.push.clone());

    // Build router
    let app = build_router(state);

    // Start server with graceful shutdown
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    tracing::info!(%addr, "Starting MyPass server");

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("Failed to bind address");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .expect("Server error");

    tracing::info!("Server shut down gracefully");
}

/// Spawn a background task that cleans up expired share links and subscriptions.
///
/// Runs every 5 minutes. Sends push notifications to devices whose temporary
/// access has expired, then deletes the expired rows from the database.
fn spawn_cleanup_task(pool: PgPool, push: Arc<PushService>) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(300));
        loop {
            interval.tick().await;

            // Clean expired share links
            match sqlx::query("DELETE FROM share_links WHERE expires_at < now()")
                .execute(&pool)
                .await
            {
                Ok(result) => {
                    let count = result.rows_affected();
                    if count > 0 {
                        tracing::info!(count, "Cleaned up expired share links");
                    }
                }
                Err(e) => tracing::error!(error = %e, "Failed to clean up expired share links"),
            }

            // Notify devices whose subscriptions have expired, then delete
            let expired: Vec<(String, String, String)> = match sqlx::query_as(
                "SELECT cs.id, cs.card_id, COALESCE(d.push_token, '') as push_token
                 FROM card_subscriptions cs
                 LEFT JOIN devices d ON d.id = cs.device_id
                 WHERE cs.expires_at IS NOT NULL AND cs.expires_at < now()",
            )
            .fetch_all(&pool)
            .await
            {
                Ok(rows) => rows,
                Err(e) => {
                    tracing::error!(error = %e, "Failed to query expired subscriptions");
                    continue;
                }
            };

            if !expired.is_empty() {
                let count = expired.len();

                // Send expiry notifications
                for (_, card_id, push_token) in &expired {
                    if !push_token.is_empty() {
                        let _ = push.notify_share_expired(push_token, card_id).await;
                    }
                }

                // Delete expired subscriptions
                match sqlx::query(
                    "DELETE FROM card_subscriptions WHERE expires_at IS NOT NULL AND expires_at < now()",
                )
                .execute(&pool)
                .await
                {
                    Ok(_) => {
                        tracing::info!(count, "Cleaned up expired subscriptions and notified devices");
                    }
                    Err(e) => {
                        tracing::error!(error = %e, "Failed to clean up expired subscriptions");
                    }
                }
            }
        }
    });
}

/// Wait for SIGTERM or Ctrl+C for graceful shutdown.
async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("Failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("Failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => tracing::info!("Received Ctrl+C, shutting down"),
        _ = terminate => tracing::info!("Received SIGTERM, shutting down"),
    }
}
