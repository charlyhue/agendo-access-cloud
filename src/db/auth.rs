//! Authentification du portail : sessions, codes par e-mail, passkeys, défis WebAuthn.

use chrono::{DateTime, Duration, Utc};
use sqlx::{FromRow, PgExecutor, PgPool};
use uuid::Uuid;

use crate::crypto;

/// Durée d'une session.
pub const SESSION_TTL: Duration = Duration::days(30);
/// Validité d'un code de connexion par e-mail.
pub const EMAIL_CODE_TTL: Duration = Duration::minutes(10);
/// Essais permis par code.
pub const EMAIL_CODE_ATTEMPTS: i32 = 5;

/// Session valide, avec son compte.
#[derive(Debug, Clone, FromRow)]
pub struct Session {
    pub id: Uuid,
    pub account_id: Uuid,
    pub email: String,
}

/// Ouvre une session ; rend le jeton en clair (pour le cookie), seul son hachage est rangé.
pub async fn create_session(
    db: impl PgExecutor<'_>,
    account: Uuid,
    user_agent: &str,
    now: DateTime<Utc>,
) -> sqlx::Result<String> {
    let token = crypto::random_token();
    sqlx::query(
        "INSERT INTO sessions (id, account_id, token_hash, user_agent, created_at, expires_at, last_seen_at)
         VALUES ($1, $2, $3, $4, $5, $6, $5)",
    )
    .bind(Uuid::new_v4())
    .bind(account)
    .bind(crypto::hash(&token))
    .bind(user_agent.chars().take(200).collect::<String>())
    .bind(now)
    .bind(now + SESSION_TTL)
    .execute(db)
    .await?;
    Ok(token)
}

/// Session du jeton, si elle est valide ; note sa dernière utilisation.
pub async fn session_by_token(db: &PgPool, token: &str, now: DateTime<Utc>) -> sqlx::Result<Option<Session>> {
    sqlx::query_as(
        "UPDATE sessions s SET last_seen_at = $2
         FROM accounts a
         WHERE s.token_hash = $1 AND a.id = s.account_id AND s.revoked_at IS NULL AND s.expires_at > $2
         RETURNING s.id, s.account_id, a.email",
    )
    .bind(crypto::hash(token))
    .bind(now)
    .fetch_optional(db)
    .await
}

/// Révoque une session du compte ; `false` si elle n'existe pas pour ce compte.
pub async fn revoke_session(db: impl PgExecutor<'_>, account: Uuid, id: Uuid, now: DateTime<Utc>) -> sqlx::Result<bool> {
    let done = sqlx::query("UPDATE sessions SET revoked_at = $3 WHERE id = $1 AND account_id = $2 AND revoked_at IS NULL")
        .bind(id)
        .bind(account)
        .bind(now)
        .execute(db)
        .await?;
    Ok(done.rows_affected() == 1)
}

fn code_hash(account: Uuid, code: &str) -> Vec<u8> {
    crypto::hash(&format!("{account}:{code}"))
}

/// Nouveau code de connexion ; les précédents cessent de valoir. Rend le code en clair.
pub async fn create_email_code(db: &PgPool, account: Uuid, now: DateTime<Utc>) -> sqlx::Result<String> {
    let mut tx = db.begin().await?;
    sqlx::query("UPDATE email_codes SET consumed_at = $2 WHERE account_id = $1 AND consumed_at IS NULL")
        .bind(account)
        .bind(now)
        .execute(&mut *tx)
        .await?;
    let code = crypto::six_digit_code();
    sqlx::query("INSERT INTO email_codes (id, account_id, code_hash, created_at, expires_at) VALUES ($1, $2, $3, $4, $5)")
        .bind(Uuid::new_v4())
        .bind(account)
        .bind(code_hash(account, &code))
        .bind(now)
        .bind(now + EMAIL_CODE_TTL)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(code)
}

/// Vérifie un code : compte un essai, et consomme le code s'il est bon. Au-delà de
/// [`EMAIL_CODE_ATTEMPTS`] essais, même le bon code est refusé.
pub async fn check_email_code(db: &PgPool, account: Uuid, code: &str, now: DateTime<Utc>) -> sqlx::Result<bool> {
    let row: Option<(Uuid, Vec<u8>, i32)> = sqlx::query_as(
        "UPDATE email_codes SET attempts = attempts + 1
         WHERE id = (SELECT id FROM email_codes
                     WHERE account_id = $1 AND consumed_at IS NULL AND expires_at > $2
                     ORDER BY created_at DESC LIMIT 1)
         RETURNING id, code_hash, attempts",
    )
    .bind(account)
    .bind(now)
    .fetch_optional(db)
    .await?;
    let Some((id, hash, attempts)) = row else { return Ok(false) };
    if attempts > EMAIL_CODE_ATTEMPTS || hash != code_hash(account, code) {
        return Ok(false);
    }
    let consumed = sqlx::query("UPDATE email_codes SET consumed_at = $2 WHERE id = $1 AND consumed_at IS NULL")
        .bind(id)
        .bind(now)
        .execute(db)
        .await?;
    Ok(consumed.rows_affected() == 1)
}
