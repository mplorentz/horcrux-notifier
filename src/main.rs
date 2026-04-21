use std::sync::Arc;

use anyhow::{Context, Result};
use horcrux_notifier::{
    build_router_with_state, config::Config, db, fcm::FcmClient, spawn_prune_task,
};
use tokio::net::TcpListener;
use tower_http::trace::TraceLayer;
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();

    let config = Config::from_env().context("loading configuration")?;
    tracing::info!(bind = %config.bind, "horcrux-notifier starting");

    let pool = db::connect(&config.database_url).await?;
    let fcm = FcmClient::from_service_account(&config.fcm_service_account_path)
        .await
        .context("initializing FCM client")?;

    let (router, state) = build_router_with_state(config.clone(), pool, Arc::new(fcm)).await?;
    let router = router.layer(TraceLayer::new_for_http());

    spawn_prune_task(state);

    let listener = TcpListener::bind(config.bind).await?;
    tracing::info!(addr = %config.bind, "listening");

    axum::serve(listener, router)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("axum::serve failed")?;

    Ok(())
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("horcrux_notifier=info,tower_http=info"));
    tracing_subscriber::registry()
        .with(filter)
        .with(fmt::layer())
        .init();
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c().await.ok();
    };

    #[cfg(unix)]
    let term = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let term = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => tracing::info!("received SIGINT, shutting down"),
        _ = term => tracing::info!("received SIGTERM, shutting down"),
    }
}
