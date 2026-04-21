pub mod auth;
pub mod config;
pub mod db;
pub mod error;
pub mod fcm;
pub mod ratelimit;
pub mod routes;
pub mod state;

use std::sync::Arc;

use anyhow::Result;
use axum::Router;
use tokio::time::{self, Duration};

use crate::{config::Config, db::Pool, fcm::FcmSender, state::AppState};

pub async fn build_router_with_state(
    config: Config,
    pool: Pool,
    fcm: Arc<dyn FcmSender>,
) -> Result<(Router, AppState)> {
    let state = AppState::new(config, pool, fcm);
    let router = routes::router(state.clone());
    Ok((router, state))
}

pub fn spawn_prune_task(state: AppState) {
    tokio::spawn(async move {
        let mut interval = time::interval(Duration::from_secs(300));
        interval.tick().await; // fire once, then at cadence
        loop {
            interval.tick().await;
            if let Err(e) = ratelimit::prune(&state.pool, &state.config).await {
                tracing::warn!(error = %e, "rate limit prune failed");
            }
        }
    });
}
