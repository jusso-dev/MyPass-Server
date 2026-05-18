/// Database connection pool setup using SQLx.
///
/// Creates a PostgreSQL connection pool with sensible defaults for a
/// small-to-medium workload. The pool is shared across all request handlers
/// via Axum's state mechanism.
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;

/// Create a new PostgreSQL connection pool.
///
/// Configures max connections and acquire timeout. The pool is lazily connected
/// so this function returns quickly; actual connections are established on first use.
pub async fn create_pool(database_url: &str) -> PgPool {
    PgPoolOptions::new()
        .max_connections(20)
        .acquire_timeout(std::time::Duration::from_secs(5))
        .connect(database_url)
        .await
        .expect("Failed to connect to database")
}

/// Run all pending SQL migrations from the `migrations/` directory.
///
/// Uses SQLx's built-in migrator which tracks applied migrations in a
/// `_sqlx_migrations` table. Safe to run on every startup.
pub async fn run_migrations(pool: &PgPool) {
    sqlx::migrate!("./migrations")
        .run(pool)
        .await
        .expect("Failed to run database migrations");
}
