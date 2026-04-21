use axum::{extract::State, Json};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    auth::AuthedJson,
    db,
    error::{ApiError, ApiResult},
    fcm::{FcmMessage, Platform},
    ratelimit,
    state::AppState,
};

const MAX_TITLE_LEN: usize = 200;
const MAX_BODY_LEN: usize = 2_000;
const MAX_EVENT_JSON_BYTES: usize = 3_072; // 3 KB, matches the client-side embed threshold

#[derive(Debug, Deserialize)]
pub struct PushRequest {
    pub recipient_pubkey: String,
    pub title: String,
    pub body: String,
    #[serde(default)]
    pub event_id: Option<String>,
    #[serde(default)]
    pub event_json: Option<Value>,
    #[serde(default)]
    pub relay_hints: Option<Vec<String>>,
}

#[derive(Debug, Serialize)]
pub struct PushResponse {
    pub status: &'static str,
    pub fcm_message_id: String,
}

pub async fn push(
    State(state): State<AppState>,
    AuthedJson(req, ctx): AuthedJson<PushRequest>,
) -> ApiResult<Json<PushResponse>> {
    let sender = ctx.pubkey.clone();
    let recipient = req.recipient_pubkey.trim().to_ascii_lowercase();
    if !is_hex_pubkey(&recipient) {
        return Err(ApiError::BadRequest(format!(
            "invalid recipient_pubkey: {:?}",
            req.recipient_pubkey
        )));
    }

    if sender == recipient {
        return Err(ApiError::BadRequest(
            "sender and recipient must be different".into(),
        ));
    }

    if req.title.is_empty() || req.title.len() > MAX_TITLE_LEN {
        return Err(ApiError::BadRequest(format!(
            "title length must be 1..={MAX_TITLE_LEN} (got {})",
            req.title.len()
        )));
    }
    if req.body.is_empty() || req.body.len() > MAX_BODY_LEN {
        return Err(ApiError::BadRequest(format!(
            "body length must be 1..={MAX_BODY_LEN} (got {})",
            req.body.len()
        )));
    }

    // We accept either (a) a full embedded event or (b) an event_id + optional
    // relay_hints. Exactly one of event_json or event_id must be present.
    let embed_event_json = if let Some(event) = req.event_json.as_ref() {
        let serialized = serde_json::to_string(event)
            .map_err(|e| ApiError::BadRequest(format!("event_json is not serializable: {e}")))?;
        if serialized.len() > MAX_EVENT_JSON_BYTES {
            return Err(ApiError::BadRequest(format!(
                "event_json too large: {} bytes (max {MAX_EVENT_JSON_BYTES})",
                serialized.len()
            )));
        }
        Some(serialized)
    } else {
        None
    };

    if embed_event_json.is_none() && req.event_id.is_none() {
        return Err(ApiError::BadRequest(
            "one of event_json or event_id must be provided".into(),
        ));
    }
    if let Some(id) = req.event_id.as_ref() {
        if !is_hex_pubkey(id) {
            return Err(ApiError::BadRequest("event_id must be 64-char hex".into()));
        }
    }

    // Consent gate.
    if !db::is_consented(&state.pool, &recipient, &sender).await? {
        return Err(ApiError::Forbidden(
            "recipient has not authorized this sender".into(),
        ));
    }

    // Rate limit gate.
    ratelimit::check_push(&state.pool, &state.config, &sender, &recipient).await?;

    // Device lookup.
    let device = db::get_device(&state.pool, &recipient)
        .await?
        .ok_or_else(|| ApiError::NotFound)?;

    let platform = Platform::parse(&device.platform).ok_or_else(|| {
        ApiError::Upstream(format!("stored platform {:?} is invalid", device.platform))
    })?;

    let mut data = serde_json::Map::new();
    data.insert("sender_pubkey".into(), json!(sender));
    data.insert("recipient_pubkey".into(), json!(recipient));
    if let Some(ev_json) = embed_event_json {
        data.insert("event_json".into(), json!(ev_json));
    }
    if let Some(id) = &req.event_id {
        data.insert("event_id".into(), json!(id));
    }
    if let Some(hints) = &req.relay_hints {
        data.insert("relay_hints".into(), json!(hints.join(",")));
    }

    let message = FcmMessage {
        token: device.device_token,
        platform,
        title: req.title,
        body: req.body,
        data: Value::Object(data),
    };

    // Record the attempt *before* dispatch so a crashed dispatch still counts
    // toward rate limits.
    db::record_push_attempt(&state.pool, &sender, &recipient).await?;

    let fcm_id = state.fcm.send(message).await.map_err(|e| {
        tracing::warn!(error = %e, "FCM dispatch failed");
        ApiError::Upstream(format!("FCM dispatch failed: {e}"))
    })?;

    tracing::info!(
        sender = %truncate(&sender),
        recipient = %truncate(&recipient),
        event_id = req.event_id.as_deref().unwrap_or("(embedded)"),
        "push delivered"
    );

    Ok(Json(PushResponse {
        status: "queued",
        fcm_message_id: fcm_id,
    }))
}

fn is_hex_pubkey(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

fn truncate(pubkey: &str) -> &str {
    &pubkey[..pubkey.len().min(8)]
}
