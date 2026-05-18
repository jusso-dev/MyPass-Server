/// Integration tests for MyPass Server.
///
/// These tests spin up the real server against a test Postgres database and
/// exercise the full HTTP API: device registration, card CRUD, subscriptions,
/// share links, owner authentication, expiry, and revocation.
///
/// Requires a running Postgres instance. Set `TEST_DATABASE_URL` env var.
/// Defaults to `postgres://mypass:mypass@localhost:5432/mypass_test`.
use std::sync::Arc;

use reqwest::Client;
use serde_json::{json, Value};
use sqlx::PgPool;

/// Set up a test database, run migrations, and return the pool.
async fn setup_db() -> PgPool {
    let database_url = std::env::var("TEST_DATABASE_URL")
        .unwrap_or_else(|_| "postgres://mypass:mypass@localhost:5432/mypass_test".to_string());

    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await
        .expect("Failed to connect to test database");

    // Clean all tables before each test run
    sqlx::query("DROP TABLE IF EXISTS share_links, card_subscriptions, cards, devices CASCADE")
        .execute(&pool)
        .await
        .expect("Failed to clean tables");

    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .expect("Failed to run migrations");

    pool
}

/// Start the server on a random port and return the base URL.
async fn start_server(pool: PgPool) -> (String, tokio::task::JoinHandle<()>) {
    let config = mypass_server::config::AppConfig {
        database_url: String::new(), // Not used, pool already created
        hmac_key: "0000000000000000000000000000000000000000000000000000000000000000".to_string(),
        fcm_project_id: None,
        fcm_client_email: None,
        fcm_private_key: None,
        port: 0,
        cors_origin: None,
    };

    let push = Arc::new(mypass_server::services::push::PushService::new(
        None, None, None,
    ));

    let state = mypass_server::AppState {
        db: pool,
        config: Arc::new(config),
        push,
    };

    let app = mypass_server::build_router(state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("Failed to bind");
    let addr = listener.local_addr().unwrap();

    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    (format!("http://{}", addr), handle)
}

/// Helper to create a client with default settings.
fn client() -> Client {
    Client::new()
}

/// Register a test device and return its device_id.
async fn register_device(base_url: &str, public_key: &str) -> String {
    let resp = client()
        .post(format!("{}/v1/devices", base_url))
        .json(&json!({ "public_key": public_key, "platform": "ios" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    body["device_id"].as_str().unwrap().to_string()
}

/// Create a test card and return (card_id, version).
async fn create_card(base_url: &str, device_id: &str, owner_secret: &str) -> (String, i64) {
    let resp = client()
        .post(format!("{}/v1/cards", base_url))
        .json(&json!({
            "owner_device_id": device_id,
            "owner_secret": owner_secret,
            "encrypted_blob": "dGVzdCBibG9i",  // "test blob" in Base64
            "blob_iv": "dGVzdGl2MTIz",          // "testiv123" in Base64
            "blob_auth_tag": "dGVzdHRhZzE2Yg==", // "testtag16b" in Base64
            "child_alias": "Test Card"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    (
        body["card_id"].as_str().unwrap().to_string(),
        body["version"].as_i64().unwrap(),
    )
}

#[tokio::test]
async fn test_health_check() {
    let pool = setup_db().await;
    let (base_url, _handle) = start_server(pool).await;

    let resp = client()
        .get(format!("{}/health", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "ok");
}

#[tokio::test]
async fn test_full_happy_path() {
    let pool = setup_db().await;
    let (base_url, _handle) = start_server(pool).await;

    // 1. Register owner device
    let owner_device_id = register_device(&base_url, "owner-public-key-base64").await;
    assert!(!owner_device_id.is_empty());

    // 2. Register device again (idempotent) — should return same id
    let owner_device_id_2 = register_device(&base_url, "owner-public-key-base64").await;
    assert_eq!(owner_device_id, owner_device_id_2);

    // 3. Register subscriber device
    let sub_device_id = register_device(&base_url, "subscriber-public-key-base64").await;

    // 4. Create a card
    let owner_secret = "my-test-owner-secret-base64encoded";
    let (card_id, version) = create_card(&base_url, &owner_device_id, owner_secret).await;
    assert_eq!(version, 1);

    // 5. Fetch card as owner
    let resp = client()
        .get(format!("{}/v1/cards/{}", base_url, card_id))
        .header("X-Owner-Secret", owner_secret)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["version"], 1);
    assert_eq!(body["encrypted_blob"], "dGVzdCBibG9i");

    // 6. Create subscription (share card with subscriber)
    let resp = client()
        .post(format!("{}/v1/cards/{}/subscriptions", base_url, card_id))
        .header("X-Owner-Secret", owner_secret)
        .json(&json!({
            "device_id": sub_device_id,
            "wrapped_key": "d3JhcHBlZC1rZXk=",
            "ephemeral_public_key": "ZXBoZW1lcmFsLWtleQ==",
            "role": "trusted"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["role"], "trusted");

    // 7. Fetch card as subscriber
    let resp = client()
        .get(format!("{}/v1/cards/{}", base_url, card_id))
        .header("X-Device-Id", &sub_device_id)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["version"], 1);

    // 8. Update card
    let resp = client()
        .put(format!("{}/v1/cards/{}", base_url, card_id))
        .header("X-Owner-Secret", owner_secret)
        .json(&json!({
            "encrypted_blob": "dXBkYXRlZCBibG9i",
            "blob_iv": "bmV3aXYxMjM0NQ==",
            "blob_auth_tag": "bmV3dGFnMTIzNDU2"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["version"], 2);

    // 9. Fetch updated card as subscriber
    let resp = client()
        .get(format!("{}/v1/cards/{}", base_url, card_id))
        .header("X-Device-Id", &sub_device_id)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["version"], 2);
    assert_eq!(body["encrypted_blob"], "dXBkYXRlZCBibG9i");

    // 10. List received subscriptions
    let resp = client()
        .get(format!("{}/v1/subscriptions/received", base_url))
        .header("X-Device-Id", &sub_device_id)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["subscriptions"].as_array().unwrap().len(), 1);
    assert_eq!(body["subscriptions"][0]["card_id"], card_id);
    // After fetching version 2, is_stale should be false
    assert_eq!(body["subscriptions"][0]["is_stale"], false);

    // 11. List cards owned by device
    let resp = client()
        .get(format!("{}/v1/cards", base_url))
        .header("X-Device-Id", &owner_device_id)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["cards"].as_array().unwrap().len(), 1);
    assert_eq!(body["cards"][0]["subscriber_count"], 1);
}

#[tokio::test]
async fn test_share_link_flow() {
    let pool = setup_db().await;
    let (base_url, _handle) = start_server(pool).await;

    let device_id = register_device(&base_url, "link-test-device-key").await;
    let owner_secret = "link-test-owner-secret";
    let (card_id, _) = create_card(&base_url, &device_id, owner_secret).await;

    // Create a share link with max_uses = 2
    let resp = client()
        .post(format!("{}/v1/cards/{}/links", base_url, card_id))
        .header("X-Owner-Secret", owner_secret)
        .json(&json!({
            "role": "temporary",
            "max_uses": 2,
            "expires_in_minutes": 60
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    let token = body["token"].as_str().unwrap().to_string();
    assert_eq!(body["max_uses"], 2);

    // Redeem link — first use
    let resp = client()
        .get(format!("{}/v1/links/{}/card", base_url, token))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["card_id"], card_id);
    assert_eq!(body["role"], "temporary");

    // Redeem link — second use
    let resp = client()
        .get(format!("{}/v1/links/{}/card", base_url, token))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Redeem link — third use (should fail, max_uses exhausted)
    let resp = client()
        .get(format!("{}/v1/links/{}/card", base_url, token))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 410); // Gone

    // Revoke a link (create a new one first)
    let resp = client()
        .post(format!("{}/v1/cards/{}/links", base_url, card_id))
        .header("X-Owner-Secret", owner_secret)
        .json(&json!({ "expires_in_minutes": 60 }))
        .send()
        .await
        .unwrap();
    let token2 = resp.json::<Value>().await.unwrap()["token"]
        .as_str()
        .unwrap()
        .to_string();

    let resp = client()
        .delete(format!(
            "{}/v1/cards/{}/links/{}",
            base_url, card_id, token2
        ))
        .header("X-Owner-Secret", owner_secret)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Redeem revoked link — should be 404
    let resp = client()
        .get(format!("{}/v1/links/{}/card", base_url, token2))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn test_owner_auth() {
    let pool = setup_db().await;
    let (base_url, _handle) = start_server(pool).await;

    let device_id = register_device(&base_url, "auth-test-device-key").await;
    let owner_secret = "correct-owner-secret";
    let (card_id, _) = create_card(&base_url, &device_id, owner_secret).await;

    // Update without X-Owner-Secret → 403
    let resp = client()
        .put(format!("{}/v1/cards/{}", base_url, card_id))
        .json(&json!({
            "encrypted_blob": "dGVzdA==",
            "blob_iv": "dGVzdA==",
            "blob_auth_tag": "dGVzdA=="
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);

    // Update with wrong secret → 403
    let resp = client()
        .put(format!("{}/v1/cards/{}", base_url, card_id))
        .header("X-Owner-Secret", "wrong-secret")
        .json(&json!({
            "encrypted_blob": "dGVzdA==",
            "blob_iv": "dGVzdA==",
            "blob_auth_tag": "dGVzdA=="
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);

    // Update with correct secret → 200
    let resp = client()
        .put(format!("{}/v1/cards/{}", base_url, card_id))
        .header("X-Owner-Secret", owner_secret)
        .json(&json!({
            "encrypted_blob": "dGVzdA==",
            "blob_iv": "dGVzdA==",
            "blob_auth_tag": "dGVzdA=="
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
}

#[tokio::test]
async fn test_expired_subscription() {
    let pool = setup_db().await;
    let (base_url, _handle) = start_server(pool).await;

    let owner_id = register_device(&base_url, "expiry-owner-key").await;
    let sub_id = register_device(&base_url, "expiry-sub-key").await;
    let owner_secret = "expiry-test-secret";
    let (card_id, _) = create_card(&base_url, &owner_id, owner_secret).await;

    // Create subscription that already expired
    let expired = chrono::Utc::now() - chrono::Duration::hours(1);
    let resp = client()
        .post(format!("{}/v1/cards/{}/subscriptions", base_url, card_id))
        .header("X-Owner-Secret", owner_secret)
        .json(&json!({
            "device_id": sub_id,
            "wrapped_key": "d3JhcHBlZA==",
            "ephemeral_public_key": "ZXBoZW1lcmFs",
            "expires_at": expired.to_rfc3339()
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Try to fetch card with expired subscription → 403
    let resp = client()
        .get(format!("{}/v1/cards/{}", base_url, card_id))
        .header("X-Device-Id", &sub_id)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
}

#[tokio::test]
async fn test_revocation() {
    let pool = setup_db().await;
    let (base_url, _handle) = start_server(pool).await;

    let owner_id = register_device(&base_url, "revoke-owner-key").await;
    let sub_id = register_device(&base_url, "revoke-sub-key").await;
    let owner_secret = "revoke-test-secret";
    let (card_id, _) = create_card(&base_url, &owner_id, owner_secret).await;

    // Create subscription
    let resp = client()
        .post(format!("{}/v1/cards/{}/subscriptions", base_url, card_id))
        .header("X-Owner-Secret", owner_secret)
        .json(&json!({
            "device_id": sub_id,
            "wrapped_key": "d3JhcHBlZA==",
            "ephemeral_public_key": "ZXBoZW1lcmFs"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let sub_body: Value = resp.json().await.unwrap();
    let subscription_id = sub_body["subscription_id"].as_str().unwrap();

    // Verify access works
    let resp = client()
        .get(format!("{}/v1/cards/{}", base_url, card_id))
        .header("X-Device-Id", &sub_id)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Revoke subscription
    let resp = client()
        .delete(format!("{}/v1/subscriptions/{}", base_url, subscription_id))
        .header("X-Owner-Secret", owner_secret)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Fetch after revocation → 403
    let resp = client()
        .get(format!("{}/v1/cards/{}", base_url, card_id))
        .header("X-Device-Id", &sub_id)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
}

#[tokio::test]
async fn test_device_push_token_update() {
    let pool = setup_db().await;
    let (base_url, _handle) = start_server(pool).await;

    let device_id = register_device(&base_url, "push-test-device-key").await;

    // Update push token
    let resp = client()
        .put(format!("{}/v1/devices/{}/push", base_url, device_id))
        .json(&json!({ "push_token": "new-fcm-token-123", "platform": "android" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Get public key
    let resp = client()
        .get(format!("{}/v1/devices/{}/public-key", base_url, device_id))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["public_key"], "push-test-device-key");
}

#[tokio::test]
async fn test_card_deletion_cascades() {
    let pool = setup_db().await;
    let (base_url, _handle) = start_server(pool).await;

    let owner_id = register_device(&base_url, "cascade-owner-key").await;
    let sub_id = register_device(&base_url, "cascade-sub-key").await;
    let owner_secret = "cascade-test-secret";
    let (card_id, _) = create_card(&base_url, &owner_id, owner_secret).await;

    // Create subscription
    client()
        .post(format!("{}/v1/cards/{}/subscriptions", base_url, card_id))
        .header("X-Owner-Secret", owner_secret)
        .json(&json!({
            "device_id": sub_id,
            "wrapped_key": "d3JhcHBlZA==",
            "ephemeral_public_key": "ZXBoZW1lcmFs"
        }))
        .send()
        .await
        .unwrap();

    // Create share link
    client()
        .post(format!("{}/v1/cards/{}/links", base_url, card_id))
        .header("X-Owner-Secret", owner_secret)
        .json(&json!({ "expires_in_minutes": 60 }))
        .send()
        .await
        .unwrap();

    // Delete card
    let resp = client()
        .delete(format!("{}/v1/cards/{}", base_url, card_id))
        .header("X-Owner-Secret", owner_secret)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Card should be gone
    let resp = client()
        .get(format!("{}/v1/cards/{}", base_url, card_id))
        .header("X-Owner-Secret", owner_secret)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn test_key_rotation() {
    let pool = setup_db().await;
    let (base_url, _handle) = start_server(pool).await;

    let owner_id = register_device(&base_url, "rotate-owner-key").await;
    let sub_id = register_device(&base_url, "rotate-sub-key").await;
    let owner_secret = "rotate-test-secret";
    let (card_id, _) = create_card(&base_url, &owner_id, owner_secret).await;

    // Create subscription
    client()
        .post(format!("{}/v1/cards/{}/subscriptions", base_url, card_id))
        .header("X-Owner-Secret", owner_secret)
        .json(&json!({
            "device_id": sub_id,
            "wrapped_key": "b2xkLXdyYXBwZWQ=",
            "ephemeral_public_key": "b2xkLWVwaGVtZXJhbA=="
        }))
        .send()
        .await
        .unwrap();

    // Rotate key
    let resp = client()
        .post(format!("{}/v1/cards/{}/rotate-key", base_url, card_id))
        .header("X-Owner-Secret", owner_secret)
        .json(&json!({
            "encrypted_blob": "bmV3LWVuY3J5cHRlZA==",
            "blob_iv": "bmV3LWl2LTEyMw==",
            "blob_auth_tag": "bmV3LXRhZy0xMjM=",
            "subscriber_keys": [{
                "device_id": sub_id,
                "wrapped_key": "bmV3LXdyYXBwZWQ=",
                "ephemeral_public_key": "bmV3LWVwaGVtZXJhbA=="
            }]
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["version"], 2);
    assert_eq!(body["rotated"], true);

    // Verify the card blob was updated
    let resp = client()
        .get(format!("{}/v1/cards/{}", base_url, card_id))
        .header("X-Device-Id", &sub_id)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["encrypted_blob"], "bmV3LWVuY3J5cHRlZA==");
}
