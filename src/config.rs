use std::{env, net::SocketAddr, path::PathBuf, str::FromStr, time::Duration};

use anyhow::{Context, Result};

#[derive(Debug, Clone)]
pub struct Config {
    pub bind: SocketAddr,
    pub database_url: String,
    pub fcm_service_account_path: PathBuf,
    pub nip98_max_age: Duration,
    pub push_pair_window: Duration,
    pub push_pair_max: u32,
    pub push_recipient_window: Duration,
    pub push_recipient_max: u32,
    pub register_window: Duration,
    pub register_max: u32,
}

impl Config {
    pub fn from_env() -> Result<Self> {
        let _ = dotenvy::dotenv();

        Ok(Self {
            bind: parse_env("HORCRUX_NOTIFIER_BIND", "0.0.0.0:8080")?,
            database_url: env_or(
                "HORCRUX_NOTIFIER_DATABASE_URL",
                "sqlite://data/horcrux_notifier.db?mode=rwc",
            ),
            fcm_service_account_path: env_required("HORCRUX_NOTIFIER_FCM_SERVICE_ACCOUNT")
                .map(PathBuf::from)?,
            nip98_max_age: Duration::from_secs(parse_env(
                "HORCRUX_NOTIFIER_NIP98_MAX_AGE_SECS",
                "60",
            )?),
            push_pair_window: Duration::from_secs(parse_env(
                "HORCRUX_NOTIFIER_PUSH_PAIR_WINDOW_SECS",
                "30",
            )?),
            push_pair_max: parse_env("HORCRUX_NOTIFIER_PUSH_PAIR_MAX", "1")?,
            push_recipient_window: Duration::from_secs(parse_env(
                "HORCRUX_NOTIFIER_PUSH_RECIPIENT_WINDOW_SECS",
                "3600",
            )?),
            push_recipient_max: parse_env("HORCRUX_NOTIFIER_PUSH_RECIPIENT_MAX", "60")?,
            register_window: Duration::from_secs(parse_env(
                "HORCRUX_NOTIFIER_REGISTER_WINDOW_SECS",
                "3600",
            )?),
            register_max: parse_env("HORCRUX_NOTIFIER_REGISTER_MAX", "10")?,
        })
    }
}

fn env_or(key: &str, fallback: &str) -> String {
    env::var(key).unwrap_or_else(|_| fallback.to_string())
}

fn env_required(key: &str) -> Result<String> {
    env::var(key).with_context(|| format!("required env var {key} is not set"))
}

fn parse_env<T>(key: &str, fallback: &str) -> Result<T>
where
    T: FromStr,
    T::Err: std::fmt::Display,
{
    let raw = env::var(key).unwrap_or_else(|_| fallback.to_string());
    raw.parse::<T>()
        .map_err(|e| anyhow::anyhow!("failed to parse {key}={raw:?}: {e}"))
}
