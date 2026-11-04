//! Journal d'audit : connexions, invitations, rattachements, révocations. Jamais de secret ni
//! d'adresse e-mail dans `detail`.

use chrono::{DateTime, Utc};
use sqlx::{PgExecutor, types::Json};
use uuid::Uuid;

pub async fn record(
    db: impl PgExecutor<'_>,
    at: DateTime<Utc>,
    event: &str,
    account: Option<Uuid>,
    house: Option<Uuid>,
    detail: serde_json::Value,
) -> sqlx::Result<()> {
    sqlx::query("INSERT INTO audit (at, account_id, house_id, event, detail) VALUES ($1, $2, $3, $4, $5)")
        .bind(at)
        .bind(account)
        .bind(house)
        .bind(event)
        .bind(Json(detail))
        .execute(db)
        .await?;
    Ok(())
}
