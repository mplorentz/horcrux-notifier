use std::{path::Path, str::FromStr, time::Duration};

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use sqlx::{
    sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous},
    SqlitePool,
};

pub type Pool = SqlitePool;

#[derive(Debug, Clone)]
pub struct Device {
    pub pubkey: String,
    pub device_token: String,
    pub platform: String,
    #[allow(dead_code)]
    pub created_at: DateTime<Utc>,
    #[allow(dead_code)]
    pub updated_at: DateTime<Utc>,
}

pub async fn connect(database_url: &str) -> Result<Pool> {
    if let Some(stripped) = database_url.strip_prefix("sqlite://") {
        let raw = stripped.split('?').next().unwrap_or(stripped);
        if !raw.is_empty() && raw != ":memory:" {
            if let Some(parent) = Path::new(raw).parent() {
                if !parent.as_os_str().is_empty() {
                    std::fs::create_dir_all(parent).with_context(|| {
                        format!("creating sqlite parent directory {}", parent.display())
                    })?;
                }
            }
        }
    }

    let opts = SqliteConnectOptions::from_str(database_url)
        .with_context(|| format!("parsing DATABASE_URL={database_url}"))?
        .create_if_missing(true)
        .journal_mode(SqliteJournalMode::Wal)
        .synchronous(SqliteSynchronous::Normal)
        .busy_timeout(Duration::from_secs(5));

    let pool = SqlitePoolOptions::new()
        .max_connections(8)
        .acquire_timeout(Duration::from_secs(10))
        .connect_with(opts)
        .await
        .context("opening sqlite pool")?;

    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .context("running migrations")?;

    Ok(pool)
}

pub async fn upsert_device(
    pool: &Pool,
    pubkey: &str,
    device_token: &str,
    platform: &str,
) -> Result<()> {
    let now = Utc::now();
    sqlx::query(
        r#"
        INSERT INTO devices (pubkey, device_token, platform, created_at, updated_at)
        VALUES (?1, ?2, ?3, ?4, ?4)
        ON CONFLICT(pubkey) DO UPDATE SET
            device_token = excluded.device_token,
            platform     = excluded.platform,
            updated_at   = excluded.updated_at
        "#,
    )
    .bind(pubkey)
    .bind(device_token)
    .bind(platform)
    .bind(now)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn delete_device(pool: &Pool, pubkey: &str) -> Result<bool> {
    let res = sqlx::query("DELETE FROM devices WHERE pubkey = ?1")
        .bind(pubkey)
        .execute(pool)
        .await?;
    Ok(res.rows_affected() > 0)
}

pub async fn get_device(pool: &Pool, pubkey: &str) -> Result<Option<Device>> {
    let row = sqlx::query_as::<_, (String, String, String, DateTime<Utc>, DateTime<Utc>)>(
        "SELECT pubkey, device_token, platform, created_at, updated_at FROM devices WHERE pubkey = ?1",
    )
    .bind(pubkey)
    .fetch_optional(pool)
    .await?;

    Ok(row.map(
        |(pubkey, device_token, platform, created_at, updated_at)| Device {
            pubkey,
            device_token,
            platform,
            created_at,
            updated_at,
        },
    ))
}

pub async fn replace_consents(
    pool: &Pool,
    recipient: &str,
    authorized_senders: &[String],
) -> Result<()> {
    let now = Utc::now();
    let mut tx = pool.begin().await?;

    sqlx::query("DELETE FROM consents WHERE recipient_pubkey = ?1")
        .bind(recipient)
        .execute(&mut *tx)
        .await?;

    for sender in authorized_senders {
        sqlx::query(
            "INSERT OR IGNORE INTO consents (recipient_pubkey, sender_pubkey, created_at)
             VALUES (?1, ?2, ?3)",
        )
        .bind(recipient)
        .bind(sender)
        .bind(now)
        .execute(&mut *tx)
        .await?;
    }

    tx.commit().await?;
    Ok(())
}

pub async fn delete_consent(pool: &Pool, recipient: &str, sender: &str) -> Result<bool> {
    let res =
        sqlx::query("DELETE FROM consents WHERE recipient_pubkey = ?1 AND sender_pubkey = ?2")
            .bind(recipient)
            .bind(sender)
            .execute(pool)
            .await?;
    Ok(res.rows_affected() > 0)
}

pub async fn is_consented(pool: &Pool, recipient: &str, sender: &str) -> Result<bool> {
    let row = sqlx::query_scalar::<_, i64>(
        "SELECT 1 FROM consents WHERE recipient_pubkey = ?1 AND sender_pubkey = ?2",
    )
    .bind(recipient)
    .bind(sender)
    .fetch_optional(pool)
    .await?;
    Ok(row.is_some())
}

pub async fn record_push_attempt(pool: &Pool, sender: &str, recipient: &str) -> Result<()> {
    sqlx::query(
        "INSERT INTO push_attempts (sender_pubkey, recipient_pubkey, attempted_at)
         VALUES (?1, ?2, ?3)",
    )
    .bind(sender)
    .bind(recipient)
    .bind(Utc::now())
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn count_push_attempts_for_pair(
    pool: &Pool,
    sender: &str,
    recipient: &str,
    since: DateTime<Utc>,
) -> Result<i64> {
    let count = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM push_attempts
         WHERE sender_pubkey = ?1 AND recipient_pubkey = ?2 AND attempted_at >= ?3",
    )
    .bind(sender)
    .bind(recipient)
    .bind(since)
    .fetch_one(pool)
    .await?;
    Ok(count)
}

pub async fn count_push_attempts_for_recipient(
    pool: &Pool,
    recipient: &str,
    since: DateTime<Utc>,
) -> Result<i64> {
    let count = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM push_attempts
         WHERE recipient_pubkey = ?1 AND attempted_at >= ?2",
    )
    .bind(recipient)
    .bind(since)
    .fetch_one(pool)
    .await?;
    Ok(count)
}

pub async fn prune_push_attempts(pool: &Pool, older_than: DateTime<Utc>) -> Result<()> {
    sqlx::query("DELETE FROM push_attempts WHERE attempted_at < ?1")
        .bind(older_than)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn record_register_attempt(pool: &Pool, pubkey: &str) -> Result<()> {
    sqlx::query("INSERT INTO register_attempts (pubkey, attempted_at) VALUES (?1, ?2)")
        .bind(pubkey)
        .bind(Utc::now())
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn count_register_attempts(
    pool: &Pool,
    pubkey: &str,
    since: DateTime<Utc>,
) -> Result<i64> {
    let count = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM register_attempts WHERE pubkey = ?1 AND attempted_at >= ?2",
    )
    .bind(pubkey)
    .bind(since)
    .fetch_one(pool)
    .await?;
    Ok(count)
}

pub async fn prune_register_attempts(pool: &Pool, older_than: DateTime<Utc>) -> Result<()> {
    sqlx::query("DELETE FROM register_attempts WHERE attempted_at < ?1")
        .bind(older_than)
        .execute(pool)
        .await?;
    Ok(())
}
