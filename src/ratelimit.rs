use anyhow::Result;
use chrono::Utc;

use crate::{config::Config, db::Pool, error::ApiError};

pub async fn check_push(
    pool: &Pool,
    config: &Config,
    sender: &str,
    recipient: &str,
) -> Result<(), ApiError> {
    let now = Utc::now();

    let pair_since = now - chrono::Duration::from_std(config.push_pair_window).unwrap();
    let pair_count =
        crate::db::count_push_attempts_for_pair(pool, sender, recipient, pair_since).await?;
    if pair_count as u32 >= config.push_pair_max {
        return Err(ApiError::RateLimited(format!(
            "per-pair rate limit: at most {} push(es) per {}s from {} to {}",
            config.push_pair_max,
            config.push_pair_window.as_secs(),
            &sender[..8.min(sender.len())],
            &recipient[..8.min(recipient.len())],
        )));
    }

    let recip_since = now - chrono::Duration::from_std(config.push_recipient_window).unwrap();
    let recip_count =
        crate::db::count_push_attempts_for_recipient(pool, recipient, recip_since).await?;
    if recip_count as u32 >= config.push_recipient_max {
        return Err(ApiError::RateLimited(format!(
            "per-recipient rate limit: at most {} push(es) per {}s",
            config.push_recipient_max,
            config.push_recipient_window.as_secs(),
        )));
    }

    Ok(())
}

pub async fn check_register(pool: &Pool, config: &Config, pubkey: &str) -> Result<(), ApiError> {
    let now = Utc::now();
    let since = now - chrono::Duration::from_std(config.register_window).unwrap();
    let count = crate::db::count_register_attempts(pool, pubkey, since).await?;
    if count as u32 >= config.register_max {
        return Err(ApiError::RateLimited(format!(
            "register rate limit: at most {} attempts per {}s",
            config.register_max,
            config.register_window.as_secs(),
        )));
    }
    Ok(())
}

pub async fn prune(pool: &Pool, config: &Config) -> Result<()> {
    let now = Utc::now();
    let keep = std::cmp::max(config.push_recipient_window, config.register_window);
    let cutoff = now - chrono::Duration::from_std(keep).unwrap();
    crate::db::prune_push_attempts(pool, cutoff).await?;
    crate::db::prune_register_attempts(pool, cutoff).await?;
    Ok(())
}
