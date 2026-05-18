/// FCM v1 push notification service for notifying devices of card updates and shares.
///
/// Push is optional — if FCM credentials aren't configured, all send operations
/// log a warning and return Ok. This ensures the server runs correctly in
/// development without Firebase setup.
///
/// Authentication uses a Google service account: we sign a JWT with the private key,
/// exchange it for an OAuth2 access token, and cache the token until near expiry.
///
/// Credentials are provided via individual env vars: FCM_PROJECT_ID, FCM_CLIENT_EMAIL,
/// FCM_PRIVATE_KEY. The private key uses literal \n for newlines in the env var.
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Service account credentials from individual env vars.
#[derive(Clone)]
struct ServiceAccountCredentials {
    client_email: String,
    private_key: String,
}

/// Cached OAuth2 access token with expiry.
struct CachedToken {
    access_token: String,
    expires_at: std::time::Instant,
}

/// Push notification service backed by FCM v1 HTTP API.
#[derive(Clone)]
pub struct PushService {
    client: reqwest::Client,
    project_id: Option<String>,
    credentials: Option<ServiceAccountCredentials>,
    cached_token: Arc<RwLock<Option<CachedToken>>>,
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    expires_in: u64,
}

impl PushService {
    /// Create a new push service from individual credential fields.
    /// If `project_id` or credentials are None, all sends become no-ops.
    pub fn new(
        project_id: Option<String>,
        client_email: Option<String>,
        private_key: Option<String>,
    ) -> Self {
        let credentials = match (client_email, private_key) {
            (Some(email), Some(key)) => {
                // Replace literal \n with actual newlines (env vars can't contain real newlines)
                let key = key.replace("\\n", "\n");
                tracing::info!(client_email = %email, "FCM service account loaded");
                Some(ServiceAccountCredentials {
                    client_email: email,
                    private_key: key,
                })
            }
            _ => {
                if project_id.is_some() {
                    tracing::warn!(
                        "FCM_PROJECT_ID set but FCM_CLIENT_EMAIL or FCM_PRIVATE_KEY missing"
                    );
                }
                None
            }
        };

        Self {
            client: reqwest::Client::new(),
            project_id,
            credentials,
            cached_token: Arc::new(RwLock::new(None)),
        }
    }

    /// Get a valid OAuth2 access token, refreshing if expired or not yet obtained.
    async fn get_access_token(&self) -> anyhow::Result<String> {
        // Check cached token
        {
            let cached = self.cached_token.read().await;
            if let Some(ref token) = *cached {
                if token.expires_at > std::time::Instant::now() + std::time::Duration::from_secs(60)
                {
                    return Ok(token.access_token.clone());
                }
            }
        }

        let creds = self
            .credentials
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("No service account credentials"))?;

        let now = chrono::Utc::now().timestamp();

        let claims = json!({
            "iss": creds.client_email,
            "scope": "https://www.googleapis.com/auth/firebase.messaging",
            "aud": "https://oauth2.googleapis.com/token",
            "iat": now,
            "exp": now + 3600,
        });

        let header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
        let key = jsonwebtoken::EncodingKey::from_rsa_pem(creds.private_key.as_bytes())?;
        let jwt = jsonwebtoken::encode(&header, &claims, &key)?;

        let resp = self
            .client
            .post("https://oauth2.googleapis.com/token")
            .form(&[
                ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
                ("assertion", &jwt),
            ])
            .send()
            .await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(anyhow::anyhow!("Token exchange failed: {status} - {body}"));
        }

        let token_resp: TokenResponse = resp.json().await?;
        let expires_at =
            std::time::Instant::now() + std::time::Duration::from_secs(token_resp.expires_in);

        let access_token = token_resp.access_token.clone();

        let mut cached = self.cached_token.write().await;
        *cached = Some(CachedToken {
            access_token: token_resp.access_token,
            expires_at,
        });

        tracing::debug!("FCM OAuth2 token refreshed");
        Ok(access_token)
    }

    /// Send a silent data push to notify a device of a card update.
    pub async fn notify_card_update(
        &self,
        push_token: &str,
        card_id: &str,
        version: i32,
    ) -> anyhow::Result<()> {
        let project_id = match &self.project_id {
            Some(id) => id,
            None => {
                tracing::warn!("FCM not configured, skipping card update push notification");
                return Ok(());
            }
        };

        let url = format!(
            "https://fcm.googleapis.com/v1/projects/{}/messages:send",
            project_id
        );

        let payload = json!({
            "message": {
                "token": push_token,
                "notification": {
                    "title": "Card updated",
                    "body": "A MyPass card you follow has been updated"
                },
                "data": {
                    "type": "card_update",
                    "card_id": card_id,
                    "version": version.to_string()
                }
            }
        });

        self.send_with_retry(&url, &payload).await
    }

    /// Send a visible notification to a device when a card is shared with them.
    pub async fn notify_new_share(&self, push_token: &str, card_id: &str) -> anyhow::Result<()> {
        let project_id = match &self.project_id {
            Some(id) => id,
            None => {
                tracing::warn!("FCM not configured, skipping new share push notification");
                return Ok(());
            }
        };

        let url = format!(
            "https://fcm.googleapis.com/v1/projects/{}/messages:send",
            project_id
        );

        let payload = json!({
            "message": {
                "token": push_token,
                "notification": {
                    "title": "New card shared",
                    "body": "Someone shared a MyPass card with you"
                },
                "data": {
                    "type": "new_share",
                    "card_id": card_id
                }
            }
        });

        self.send_with_retry(&url, &payload).await
    }

    /// Send a visible notification to a device when a card they subscribe to is deleted.
    pub async fn notify_card_deleted(&self, push_token: &str, card_id: &str) -> anyhow::Result<()> {
        let project_id = match &self.project_id {
            Some(id) => id,
            None => {
                tracing::warn!("FCM not configured, skipping card deleted push notification");
                return Ok(());
            }
        };

        let url = format!(
            "https://fcm.googleapis.com/v1/projects/{}/messages:send",
            project_id
        );

        let payload = json!({
            "message": {
                "token": push_token,
                "notification": {
                    "title": "Card removed",
                    "body": "A MyPass card shared with you has been deleted"
                },
                "data": {
                    "type": "card_deleted",
                    "card_id": card_id
                }
            }
        });

        self.send_with_retry(&url, &payload).await
    }

    /// Send a notification to a device when their temporary share has expired.
    pub async fn notify_share_expired(
        &self,
        push_token: &str,
        card_id: &str,
    ) -> anyhow::Result<()> {
        let project_id = match &self.project_id {
            Some(id) => id,
            None => {
                tracing::warn!("FCM not configured, skipping share expired push notification");
                return Ok(());
            }
        };

        let url = format!(
            "https://fcm.googleapis.com/v1/projects/{}/messages:send",
            project_id
        );

        let payload = json!({
            "message": {
                "token": push_token,
                "notification": {
                    "title": "Access expired",
                    "body": "Your temporary access to a MyPass card has expired"
                },
                "data": {
                    "type": "share_expired",
                    "card_id": card_id
                }
            }
        });

        self.send_with_retry(&url, &payload).await
    }

    /// Send a push notification with exponential backoff retry (up to 3 attempts).
    async fn send_with_retry(&self, url: &str, payload: &serde_json::Value) -> anyhow::Result<()> {
        let access_token = match self.get_access_token().await {
            Ok(token) => token,
            Err(e) => {
                tracing::error!(error = %e, "Failed to get FCM access token");
                return Err(e);
            }
        };

        let mut delay = std::time::Duration::from_secs(1);

        for attempt in 1..=3 {
            match self
                .client
                .post(url)
                .bearer_auth(&access_token)
                .json(payload)
                .send()
                .await
            {
                Ok(resp) if resp.status().is_success() => {
                    tracing::debug!("Push notification sent successfully");
                    return Ok(());
                }
                Ok(resp) if resp.status().is_server_error() && attempt < 3 => {
                    tracing::warn!(
                        attempt,
                        status = %resp.status(),
                        "FCM transient error, retrying"
                    );
                    tokio::time::sleep(delay).await;
                    delay *= 2;
                }
                Ok(resp) => {
                    let status = resp.status();
                    let body = resp.text().await.unwrap_or_default();
                    tracing::error!(%status, %body, "FCM push notification failed");
                    return Err(anyhow::anyhow!("FCM error: {status}"));
                }
                Err(e) if attempt < 3 => {
                    tracing::warn!(attempt, error = %e, "FCM request failed, retrying");
                    tokio::time::sleep(delay).await;
                    delay *= 2;
                }
                Err(e) => {
                    tracing::error!(error = %e, "FCM push notification request failed");
                    return Err(e.into());
                }
            }
        }
        Ok(())
    }
}

/// Shared push service wrapped in Arc for use across handlers.
pub type SharedPushService = Arc<PushService>;
