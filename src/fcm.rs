//! FCM v1 HTTP API client.
//!
//! Uses a Google service account JSON to mint short-lived OAuth2 bearer
//! tokens via the RS256 JWT grant flow, then POSTs to
//! `https://fcm.googleapis.com/v1/projects/{project_id}/messages:send`.
//!
//! This is a thin, single-file client so the notifier has no dependency on
//! a heavyweight GCP SDK. See:
//! <https://firebase.google.com/docs/cloud-messaging/auth-server>

use std::{path::Path, sync::Arc, time::Duration};

use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use chrono::Utc;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::sync::Mutex;

const FCM_SCOPE: &str = "https://www.googleapis.com/auth/firebase.messaging";
const TOKEN_URL: &str = "https://oauth2.googleapis.com/token";
const TOKEN_TTL_SECS: i64 = 3600;

#[derive(Debug, Clone, Deserialize)]
struct ServiceAccount {
    client_email: String,
    private_key: String,
    project_id: String,
    token_uri: Option<String>,
}

#[derive(Debug, Serialize)]
struct JwtClaims<'a> {
    iss: &'a str,
    scope: &'a str,
    aud: &'a str,
    exp: i64,
    iat: i64,
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
    expires_in: i64,
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Platform {
    Android,
    Ios,
}

impl Platform {
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "android" => Some(Self::Android),
            "ios" => Some(Self::Ios),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Android => "android",
            Self::Ios => "ios",
        }
    }
}

#[derive(Debug, Clone)]
pub struct FcmMessage {
    pub token: String,
    pub platform: Platform,
    pub title: String,
    pub body: String,
    pub data: Value,
}

#[async_trait]
pub trait FcmSender: Send + Sync + 'static {
    async fn send(&self, message: FcmMessage) -> Result<String>;
}

#[derive(Clone)]
pub struct FcmClient {
    inner: Arc<Inner>,
}

struct Inner {
    http: Client,
    account: ServiceAccount,
    encoding_key: EncodingKey,
    cache: Mutex<Option<CachedToken>>,
}

#[derive(Clone)]
struct CachedToken {
    value: String,
    expires_at: chrono::DateTime<Utc>,
}

impl FcmClient {
    pub async fn from_service_account(path: &Path) -> Result<Self> {
        let contents = tokio::fs::read(path)
            .await
            .with_context(|| format!("reading service account JSON from {}", path.display()))?;
        let account: ServiceAccount =
            serde_json::from_slice(&contents).context("parsing service account JSON")?;
        let encoding_key = EncodingKey::from_rsa_pem(account.private_key.as_bytes())
            .context("loading RSA private key from service account")?;

        let http = Client::builder()
            .timeout(Duration::from_secs(15))
            .user_agent("horcrux-notifier/0.1")
            .build()?;

        Ok(Self {
            inner: Arc::new(Inner {
                http,
                account,
                encoding_key,
                cache: Mutex::new(None),
            }),
        })
    }

    pub fn project_id(&self) -> &str {
        &self.inner.account.project_id
    }

    async fn bearer_token(&self) -> Result<String> {
        let mut cache = self.inner.cache.lock().await;
        if let Some(cached) = cache.as_ref() {
            if cached.expires_at > Utc::now() + chrono::Duration::seconds(60) {
                return Ok(cached.value.clone());
            }
        }

        let now = Utc::now().timestamp();
        let claims = JwtClaims {
            iss: &self.inner.account.client_email,
            scope: FCM_SCOPE,
            aud: self.inner.account.token_uri.as_deref().unwrap_or(TOKEN_URL),
            exp: now + TOKEN_TTL_SECS,
            iat: now,
        };
        let header = Header::new(Algorithm::RS256);
        let assertion = encode(&header, &claims, &self.inner.encoding_key)
            .context("signing OAuth2 assertion JWT")?;

        let token_url = self
            .inner
            .account
            .token_uri
            .clone()
            .unwrap_or_else(|| TOKEN_URL.to_string());

        let resp = self
            .inner
            .http
            .post(&token_url)
            .form(&[
                ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
                ("assertion", assertion.as_str()),
            ])
            .send()
            .await
            .context("requesting OAuth2 access token")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(anyhow!(
                "google OAuth2 token exchange failed ({status}): {body}"
            ));
        }

        let body: TokenResponse = resp.json().await.context("parsing token response")?;
        let expires_at = Utc::now() + chrono::Duration::seconds(body.expires_in);
        *cache = Some(CachedToken {
            value: body.access_token.clone(),
            expires_at,
        });

        Ok(body.access_token)
    }

    fn build_payload(message: &FcmMessage) -> Value {
        let data: Value = match &message.data {
            Value::Object(map) => {
                // FCM `data` requires string values.
                let stringified: serde_json::Map<String, Value> = map
                    .iter()
                    .map(|(k, v)| {
                        let s = match v {
                            Value::String(s) => s.clone(),
                            other => other.to_string(),
                        };
                        (k.clone(), Value::String(s))
                    })
                    .collect();
                Value::Object(stringified)
            }
            _ => Value::Object(serde_json::Map::new()),
        };

        let mut msg = json!({
            "token": message.token,
            "notification": {
                "title": message.title,
                "body": message.body,
            },
            "data": data,
        });

        match message.platform {
            Platform::Android => {
                msg["android"] = json!({ "priority": "high" });
            }
            Platform::Ios => {
                msg["apns"] = json!({
                    "headers": {
                        "apns-priority": "10",
                        "apns-push-type": "alert",
                    },
                    "payload": {
                        "aps": {
                            "sound": "default",
                        }
                    }
                });
            }
        }

        json!({ "message": msg })
    }
}

#[async_trait]
impl FcmSender for FcmClient {
    async fn send(&self, message: FcmMessage) -> Result<String> {
        let token = self.bearer_token().await?;
        let url = format!(
            "https://fcm.googleapis.com/v1/projects/{}/messages:send",
            self.project_id()
        );
        let body = Self::build_payload(&message);

        let resp = self
            .inner
            .http
            .post(&url)
            .bearer_auth(token)
            .json(&body)
            .send()
            .await
            .context("sending FCM request")?;

        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        if !status.is_success() {
            return Err(anyhow!("FCM request failed ({status}): {text}"));
        }

        let parsed: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
        let name = parsed
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        Ok(name)
    }
}

/// An in-memory sender used by tests that captures every message.
#[cfg(any(test, feature = "test-util"))]
pub mod test_util {
    use std::sync::Arc;

    use tokio::sync::Mutex;

    use super::*;

    #[derive(Clone, Default)]
    pub struct MockSender {
        pub messages: Arc<Mutex<Vec<FcmMessage>>>,
    }

    #[async_trait]
    impl FcmSender for MockSender {
        async fn send(&self, message: FcmMessage) -> anyhow::Result<String> {
            self.messages.lock().await.push(message);
            Ok("projects/test/messages/1".into())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn android_payload_shape() {
        let msg = FcmMessage {
            token: "tok".into(),
            platform: Platform::Android,
            title: "hi".into(),
            body: "there".into(),
            data: json!({ "event_id": "abc", "count": 1 }),
        };
        let p = FcmClient::build_payload(&msg);
        assert_eq!(p["message"]["token"], "tok");
        assert_eq!(p["message"]["android"]["priority"], "high");
        assert_eq!(p["message"]["data"]["event_id"], "abc");
        assert_eq!(p["message"]["data"]["count"], "1");
        assert!(p["message"].get("apns").is_none());
    }

    #[test]
    fn ios_payload_shape() {
        let msg = FcmMessage {
            token: "tok".into(),
            platform: Platform::Ios,
            title: "hi".into(),
            body: "there".into(),
            data: json!({ "event_id": "abc" }),
        };
        let p = FcmClient::build_payload(&msg);
        assert_eq!(p["message"]["apns"]["headers"]["apns-priority"], "10");
        assert_eq!(p["message"]["apns"]["payload"]["aps"]["sound"], "default");
    }
}
