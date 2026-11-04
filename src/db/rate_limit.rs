//! Débit à fenêtre fixe, en base pour être partagé entre instances.

use chrono::{DateTime, Duration, Utc};
use sqlx::PgPool;

/// Compte un passage pour `key` ; `true` s'il reste sous `limit` dans la fenêtre courante.
pub async fn hit(db: &PgPool, key: &str, window: Duration, limit: u32, now: DateTime<Utc>) -> sqlx::Result<bool> {
    let secs = window.num_seconds().max(1);
    let start = DateTime::from_timestamp(now.timestamp().div_euclid(secs) * secs, 0).unwrap_or(now);
    let count: i32 = sqlx::query_scalar(
        "INSERT INTO rate_limits (key, window_start, count) VALUES ($1, $2, 1)
         ON CONFLICT (key, window_start) DO UPDATE SET count = rate_limits.count + 1
         RETURNING count",
    )
    .bind(key)
    .bind(start)
    .fetch_one(db)
    .await?;
    // Ménage occasionnel des fenêtres passées (une requête sur cent).
    if rand::random::<u8>() < 3 {
        sqlx::query("DELETE FROM rate_limits WHERE window_start < $1")
            .bind(now - Duration::days(1))
            .execute(db)
            .await?;
    }
    Ok(i64::from(count) <= i64::from(limit))
}
