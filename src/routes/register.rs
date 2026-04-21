use axum::{extract::State, http::StatusCode, Json};
use serde::{Deserialize, Serialize};

use crate::{
    auth::{AuthedEmpty, AuthedJson},
    db,
    error::{ApiError, ApiResult},
    fcm::Platform,
    ratelimit,
    state::AppState,
};

#[derive(Debug, Deserialize)]
pub struct RegisterRequest {
    pub device_token: String,
    pub platform: String,
}

#[derive(Debug, Serialize)]
pub struct RegisterResponse {
    pub pubkey: String,
    pub platform: String,
}

pub async fn register(
    State(state): State<AppState>,
    AuthedJson(req, ctx): AuthedJson<RegisterRequest>,
) -> ApiResult<(StatusCode, Json<RegisterResponse>)> {
    if req.device_token.trim().is_empty() {
        return Err(ApiError::BadRequest(
            "device_token must not be empty".into(),
        ));
    }

    let platform = Platform::parse(&req.platform).ok_or_else(|| {
        ApiError::BadRequest(format!(
            "platform must be 'android' or 'ios' (got {:?})",
            req.platform
        ))
    })?;

    ratelimit::check_register(&state.pool, &state.config, &ctx.pubkey).await?;
    db::record_register_attempt(&state.pool, &ctx.pubkey).await?;

    db::upsert_device(
        &state.pool,
        &ctx.pubkey,
        &req.device_token,
        platform.as_str(),
    )
    .await?;

    tracing::info!(pubkey = %truncate(&ctx.pubkey), platform = %platform.as_str(), "device registered");

    Ok((
        StatusCode::OK,
        Json(RegisterResponse {
            pubkey: ctx.pubkey,
            platform: platform.as_str().to_string(),
        }),
    ))
}

pub async fn unregister(
    State(state): State<AppState>,
    AuthedEmpty(ctx): AuthedEmpty,
) -> ApiResult<StatusCode> {
    let removed = db::delete_device(&state.pool, &ctx.pubkey).await?;
    if removed {
        tracing::info!(pubkey = %truncate(&ctx.pubkey), "device unregistered");
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(ApiError::NotFound)
    }
}

fn truncate(pubkey: &str) -> &str {
    &pubkey[..pubkey.len().min(8)]
}
