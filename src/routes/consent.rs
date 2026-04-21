use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};

use crate::{
    auth::{AuthedEmpty, AuthedJson},
    db,
    error::{ApiError, ApiResult},
    state::AppState,
};

const MAX_CONSENTS: usize = 2_000;

#[derive(Debug, Deserialize)]
pub struct ReplaceConsentRequest {
    pub authorized_senders: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct ReplaceConsentResponse {
    pub authorized_senders: Vec<String>,
}

pub async fn replace_consent(
    State(state): State<AppState>,
    AuthedJson(req, ctx): AuthedJson<ReplaceConsentRequest>,
) -> ApiResult<Json<ReplaceConsentResponse>> {
    if req.authorized_senders.len() > MAX_CONSENTS {
        return Err(ApiError::BadRequest(format!(
            "authorized_senders too large: {} (max {MAX_CONSENTS})",
            req.authorized_senders.len()
        )));
    }

    let mut normalized = Vec::with_capacity(req.authorized_senders.len());
    for sender in &req.authorized_senders {
        let s = sender.trim().to_ascii_lowercase();
        if !is_hex_pubkey(&s) {
            return Err(ApiError::BadRequest(format!(
                "invalid sender pubkey: {sender:?} (must be 64-char hex)"
            )));
        }
        normalized.push(s);
    }
    normalized.sort();
    normalized.dedup();

    db::replace_consents(&state.pool, &ctx.pubkey, &normalized).await?;
    tracing::info!(
        pubkey = %truncate(&ctx.pubkey),
        count = normalized.len(),
        "consent list replaced"
    );
    Ok(Json(ReplaceConsentResponse {
        authorized_senders: normalized,
    }))
}

pub async fn delete_consent(
    State(state): State<AppState>,
    Path(sender_pubkey): Path<String>,
    AuthedEmpty(ctx): AuthedEmpty,
) -> ApiResult<StatusCode> {
    let sender = sender_pubkey.trim().to_ascii_lowercase();
    if !is_hex_pubkey(&sender) {
        return Err(ApiError::BadRequest(format!(
            "invalid sender pubkey: {sender_pubkey:?}"
        )));
    }
    let removed = db::delete_consent(&state.pool, &ctx.pubkey, &sender).await?;
    if removed {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(ApiError::NotFound)
    }
}

fn is_hex_pubkey(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

fn truncate(pubkey: &str) -> &str {
    &pubkey[..pubkey.len().min(8)]
}
