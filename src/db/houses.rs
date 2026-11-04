//! Maisons et codes de rattachement.

use agendo_access_protocol::api::{ENROLLMENT_CODE_TTL_SECS, house_host};
use chrono::{DateTime, Duration, Utc};
use sqlx::{FromRow, PgConnection, PgExecutor, PgPool};
use uuid::Uuid;

use crate::crypto;

#[derive(Debug, Clone, FromRow)]
pub struct House {
    pub id: Uuid,
    pub account_id: Option<Uuid>,
    pub label: String,
    pub host: String,
    pub name: String,
    /// Clé publique Ed25519 de la maison (base64url).
    pub public_key: String,
    pub enrolled_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub last_token_at: Option<DateTime<Utc>>,
}

macro_rules! columns {
    () => {
        "id, account_id, label, host, name, public_key, enrolled_at, revoked_at, last_token_at"
    };
}

pub async fn by_id(db: impl PgExecutor<'_>, id: Uuid) -> sqlx::Result<Option<House>> {
    sqlx::query_as(concat!("SELECT ", columns!(), " FROM houses WHERE id = $1")).bind(id).fetch_optional(db).await
}

/// Maison par nom d'hôte complet ou par étiquette.
pub async fn by_host_or_label(db: impl PgExecutor<'_>, value: &str) -> sqlx::Result<Option<House>> {
    sqlx::query_as(concat!("SELECT ", columns!(), " FROM houses WHERE host = $1 OR label = $1"))
        .bind(value)
        .fetch_optional(db)
        .await
}

/// Maisons du compte, révoquées comprises (les plus récentes d'abord).
pub async fn of_account(db: impl PgExecutor<'_>, account: Uuid) -> sqlx::Result<Vec<House>> {
    sqlx::query_as(concat!("SELECT ", columns!(), " FROM houses WHERE account_id = $1 ORDER BY enrolled_at DESC, name"))
        .bind(account)
        .fetch_all(db)
        .await
}

/// Nouveau code de rattachement (15 min, usage unique) ; rend le code en clair.
pub async fn create_enrollment_code(db: &PgPool, account: Uuid, now: DateTime<Utc>) -> sqlx::Result<(String, DateTime<Utc>)> {
    let expires = now + Duration::seconds(ENROLLMENT_CODE_TTL_SECS);
    loop {
        let code = crypto::enrollment_code();
        let done = sqlx::query(
            "INSERT INTO enrollment_codes (id, account_id, code_hash, created_at, expires_at) VALUES ($1, $2, $3, $4, $5)
             ON CONFLICT (code_hash) DO NOTHING",
        )
        .bind(Uuid::new_v4())
        .bind(account)
        .bind(crypto::hash(&code))
        .bind(now)
        .bind(expires)
        .execute(db)
        .await?;
        // Collision (improbable, ~10¹² codes) avec un code ancien : on en tire un autre.
        if done.rows_affected() == 1 {
            return Ok((code, expires));
        }
    }
}

/// Consomme un code (déjà remis en forme) ; rend le code et le compte qui l'a demandé.
pub async fn consume_enrollment_code(db: &mut PgConnection, code: &str, now: DateTime<Utc>) -> sqlx::Result<Option<(Uuid, Uuid)>> {
    sqlx::query_as(
        "UPDATE enrollment_codes SET consumed_at = $2
         WHERE code_hash = $1 AND consumed_at IS NULL AND expires_at > $2
         RETURNING id, account_id",
    )
    .bind(crypto::hash(code))
    .bind(now)
    .fetch_optional(db)
    .await
}

/// Échec de la création d'une maison.
#[derive(Debug)]
pub enum InsertError {
    /// Cette clé publique est déjà celle d'une maison.
    KeyTaken,
    Db(sqlx::Error),
}

impl From<sqlx::Error> for InsertError {
    fn from(e: sqlx::Error) -> Self {
        Self::Db(e)
    }
}

/// Crée la maison avec une étiquette tirée au hasard, jamais réattribuée (nouveau tirage en
/// cas de collision).
pub async fn insert(
    db: &mut PgConnection,
    account: Uuid,
    zone: &str,
    name: &str,
    public_key: &str,
    now: DateTime<Utc>,
) -> Result<House, InsertError> {
    loop {
        let taken: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM houses WHERE public_key = $1)")
            .bind(public_key)
            .fetch_one(&mut *db)
            .await?;
        if taken {
            return Err(InsertError::KeyTaken);
        }
        let label = crypto::house_label();
        let house: Option<House> = sqlx::query_as(concat!(
            "INSERT INTO houses (id, account_id, label, host, name, public_key, enrolled_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7) ON CONFLICT DO NOTHING RETURNING ",
            columns!()
        ))
        .bind(Uuid::new_v4())
        .bind(account)
        .bind(&label)
        .bind(house_host(&label, zone))
        .bind(name)
        .bind(public_key)
        .bind(now)
        .fetch_optional(&mut *db)
        .await?;
        if let Some(house) = house {
            return Ok(house);
        }
    }
}

/// Révoque la maison (du compte s'il est donné) ; `false` si elle n'existe pas ou l'est déjà.
pub async fn revoke(db: impl PgExecutor<'_>, id: Uuid, account: Option<Uuid>, now: DateTime<Utc>) -> sqlx::Result<bool> {
    let done = sqlx::query(
        "UPDATE houses SET revoked_at = $3
         WHERE id = $1 AND revoked_at IS NULL AND ($2::uuid IS NULL OR account_id = $2)",
    )
    .bind(id)
    .bind(account)
    .bind(now)
    .execute(db)
    .await?;
    Ok(done.rows_affected() == 1)
}

/// Note la délivrance de jetons.
pub async fn tokens_issued(db: impl PgExecutor<'_>, id: Uuid, now: DateTime<Utc>) -> sqlx::Result<()> {
    sqlx::query("UPDATE houses SET last_token_at = $2 WHERE id = $1").bind(id).bind(now).execute(db).await?;
    Ok(())
}
