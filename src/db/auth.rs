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

/// Validité d'un défi WebAuthn.
pub const CHALLENGE_TTL: Duration = Duration::minutes(5);

/// Usage d'un défi : une cérémonie ne peut pas en finir une autre.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Purpose {
    RegisterInvitation,
    RegisterAccount,
    Login,
}

impl Purpose {
    fn as_str(self) -> &'static str {
        match self {
            Purpose::RegisterInvitation => "register_invitation",
            Purpose::RegisterAccount => "register_account",
            Purpose::Login => "login",
        }
    }
}

/// Défi rattaché, selon l'usage, à un compte ou à une invitation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, FromRow)]
pub struct Challenge {
    pub account_id: Option<Uuid>,
    pub invitation_id: Option<Uuid>,
}

/// Nouveau défi de 32 octets, valable [`CHALLENGE_TTL`].
pub async fn create_challenge(
    db: impl PgExecutor<'_>,
    purpose: Purpose,
    owner: Challenge,
    now: DateTime<Utc>,
) -> sqlx::Result<Vec<u8>> {
    let challenge = crypto::random_bytes::<32>().to_vec();
    sqlx::query(
        "INSERT INTO webauthn_challenges (challenge, purpose, account_id, invitation_id, expires_at) VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(&challenge)
    .bind(purpose.as_str())
    .bind(owner.account_id)
    .bind(owner.invitation_id)
    .bind(now + CHALLENGE_TTL)
    .execute(db)
    .await?;
    Ok(challenge)
}

/// Consomme un défi (usage unique) ; `None` s'il est inconnu, d'un autre usage ou expiré.
pub async fn take_challenge(
    db: impl PgExecutor<'_>,
    challenge: &[u8],
    purpose: Purpose,
    now: DateTime<Utc>,
) -> sqlx::Result<Option<Challenge>> {
    sqlx::query_as(
        "DELETE FROM webauthn_challenges WHERE challenge = $1 AND purpose = $2 AND expires_at > $3
         RETURNING account_id, invitation_id",
    )
    .bind(challenge)
    .bind(purpose.as_str())
    .bind(now)
    .fetch_optional(db)
    .await
}

/// Passkey enregistrée.
#[derive(Debug, Clone, FromRow)]
pub struct Passkey {
    pub id: Uuid,
    pub account_id: Uuid,
    pub credential_id: Vec<u8>,
    pub public_key: Vec<u8>,
    pub algorithm: i64,
    pub sign_count: i64,
    pub backup_eligible: bool,
    pub name: String,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
}

macro_rules! passkey_columns {
    () => {
        "id, account_id, credential_id, public_key, algorithm, sign_count, backup_eligible, name, created_at, last_used_at"
    };
}

/// Range une passkey vérifiée ; `false` si cet identifiant est déjà enregistré.
pub async fn insert_passkey(
    db: impl PgExecutor<'_>,
    account: Uuid,
    credential: &agendo_webauthn::NewCredential,
    name: &str,
    now: DateTime<Utc>,
) -> sqlx::Result<bool> {
    let done = sqlx::query(
        "INSERT INTO passkeys (id, account_id, credential_id, public_key, algorithm, sign_count, backup_eligible,
                               transports, name, created_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) ON CONFLICT (credential_id) DO NOTHING",
    )
    .bind(Uuid::new_v4())
    .bind(account)
    .bind(&credential.id)
    .bind(&credential.public_key)
    .bind(credential.algorithm)
    .bind(i64::from(credential.sign_count))
    .bind(credential.backup_eligible)
    .bind(&credential.transports)
    .bind(name)
    .bind(now)
    .execute(db)
    .await?;
    Ok(done.rows_affected() == 1)
}

pub async fn passkey_by_credential(db: impl PgExecutor<'_>, credential_id: &[u8]) -> sqlx::Result<Option<Passkey>> {
    sqlx::query_as(concat!("SELECT ", passkey_columns!(), " FROM passkeys WHERE credential_id = $1"))
        .bind(credential_id)
        .fetch_optional(db)
        .await
}

pub async fn passkeys_of(db: impl PgExecutor<'_>, account: Uuid) -> sqlx::Result<Vec<Passkey>> {
    sqlx::query_as(concat!("SELECT ", passkey_columns!(), " FROM passkeys WHERE account_id = $1 ORDER BY created_at, name"))
        .bind(account)
        .fetch_all(db)
        .await
}

/// Note une authentification réussie (nouveau compteur, date).
pub async fn passkey_used(db: impl PgExecutor<'_>, id: Uuid, sign_count: u32, now: DateTime<Utc>) -> sqlx::Result<()> {
    sqlx::query("UPDATE passkeys SET sign_count = $2, last_used_at = $3 WHERE id = $1")
        .bind(id)
        .bind(i64::from(sign_count))
        .bind(now)
        .execute(db)
        .await?;
    Ok(())
}

/// Issue du retrait d'une passkey.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Removal {
    Removed,
    NotFound,
    /// La dernière passkey du compte reste.
    LastOne,
}

pub async fn remove_passkey(db: &PgPool, account: Uuid, id: Uuid) -> sqlx::Result<Removal> {
    let mut tx = db.begin().await?;
    // Verrou sur les passkeys du compte : deux retraits simultanés ne laissent pas zéro passkey.
    let ids: Vec<Uuid> = sqlx::query_scalar("SELECT id FROM passkeys WHERE account_id = $1 FOR UPDATE")
        .bind(account)
        .fetch_all(&mut *tx)
        .await?;
    if !ids.contains(&id) {
        return Ok(Removal::NotFound);
    }
    if ids.len() == 1 {
        return Ok(Removal::LastOne);
    }
    sqlx::query("DELETE FROM passkeys WHERE id = $1").bind(id).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(Removal::Removed)
}
