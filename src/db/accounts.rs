//! Comptes et invitations.

use chrono::{DateTime, Duration, Utc};
use sqlx::{FromRow, PgConnection, PgExecutor};
use uuid::Uuid;

use crate::crypto;

/// Validité d'une invitation.
pub const INVITATION_TTL: Duration = Duration::days(7);

#[derive(Debug, Clone, FromRow)]
pub struct Account {
    pub id: Uuid,
    pub email: String,
    pub status: String,
    pub subscription_active: bool,
    pub subscription_source: String,
    pub webauthn_user_id: Vec<u8>,
    pub created_at: DateTime<Utc>,
    pub activated_at: Option<DateTime<Utc>>,
}

impl Account {
    pub fn is_active(&self) -> bool {
        self.status == "active"
    }
}

/// Adresse remise en forme (minuscules, sans blancs autour) ; `None` si ce n'est pas une
/// adresse plausible.
pub fn normalize_email(input: &str) -> Option<String> {
    let email = input.trim().to_lowercase();
    let (local, domain) = email.split_once('@')?;
    let plausible = !local.is_empty()
        && domain.contains('.')
        && !domain.starts_with('.')
        && !domain.ends_with('.')
        && !domain.contains('@')
        && email.len() <= 254
        && !email.chars().any(|c| c.is_whitespace() || c.is_control());
    plausible.then_some(email)
}

/// Colonnes d'[`Account`], dans des requêtes littérales (`concat!`).
macro_rules! columns {
    () => {
        "id, email, status, subscription_active, subscription_source, webauthn_user_id, created_at, activated_at"
    };
}

pub async fn by_email(db: impl PgExecutor<'_>, email: &str) -> sqlx::Result<Option<Account>> {
    sqlx::query_as(concat!("SELECT ", columns!(), " FROM accounts WHERE email = $1")).bind(email).fetch_optional(db).await
}

pub async fn by_id(db: impl PgExecutor<'_>, id: Uuid) -> sqlx::Result<Option<Account>> {
    sqlx::query_as(concat!("SELECT ", columns!(), " FROM accounts WHERE id = $1")).bind(id).fetch_optional(db).await
}

pub async fn all(db: impl PgExecutor<'_>) -> sqlx::Result<Vec<Account>> {
    sqlx::query_as(concat!("SELECT ", columns!(), " FROM accounts ORDER BY created_at, email")).fetch_all(db).await
}

/// Nouveau compte `invited`, abonnement actif posé à la main.
pub async fn create_invited(db: impl PgExecutor<'_>, email: &str, now: DateTime<Utc>) -> sqlx::Result<Account> {
    sqlx::query_as(concat!(
        "INSERT INTO accounts (id, email, status, subscription_active, subscription_source, webauthn_user_id, created_at)
         VALUES ($1, $2, 'invited', true, 'manual', $3, $4) RETURNING ",
        columns!()
    ))
    .bind(Uuid::new_v4())
    .bind(email)
    .bind(crypto::random_bytes::<32>().to_vec())
    .bind(now)
    .fetch_one(db)
    .await
}

pub async fn set_subscription(db: impl PgExecutor<'_>, id: Uuid, active: bool) -> sqlx::Result<()> {
    sqlx::query("UPDATE accounts SET subscription_active = $2 WHERE id = $1").bind(id).bind(active).execute(db).await?;
    Ok(())
}

/// Nouvelle invitation pour le compte ; les précédentes, non utilisées, cessent de valoir.
/// Rend le jeton en clair (pour le lien), seul son hachage est rangé.
pub async fn create_invitation(db: &mut PgConnection, account: Uuid, now: DateTime<Utc>) -> sqlx::Result<String> {
    sqlx::query("UPDATE invitations SET consumed_at = $2 WHERE account_id = $1 AND consumed_at IS NULL")
        .bind(account)
        .bind(now)
        .execute(&mut *db)
        .await?;
    let token = crypto::random_token();
    sqlx::query(
        "INSERT INTO invitations (id, account_id, token_hash, created_at, expires_at) VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(Uuid::new_v4())
    .bind(account)
    .bind(crypto::hash(&token))
    .bind(now)
    .bind(now + INVITATION_TTL)
    .execute(&mut *db)
    .await?;
    Ok(token)
}

/// État d'un lien d'invitation.
#[derive(Debug, Clone)]
pub enum Invitation {
    /// Utilisable : l'invitation et son compte.
    Valid { id: Uuid, account: Account },
    Expired,
    Used,
    Unknown,
}

#[derive(FromRow)]
struct InvitationRow {
    invitation_id: Uuid,
    expires_at: DateTime<Utc>,
    consumed_at: Option<DateTime<Utc>>,
    #[sqlx(flatten)]
    account: Account,
}

/// Invitation du lien, avec son compte.
pub async fn invitation(db: impl PgExecutor<'_>, token: &str, now: DateTime<Utc>) -> sqlx::Result<Invitation> {
    let row: Option<InvitationRow> = sqlx::query_as(
        "SELECT i.id AS invitation_id, i.expires_at, i.consumed_at,
                a.id, a.email, a.status, a.subscription_active, a.subscription_source, a.webauthn_user_id,
                a.created_at, a.activated_at
         FROM invitations i JOIN accounts a ON a.id = i.account_id
         WHERE i.token_hash = $1",
    )
    .bind(crypto::hash(token))
    .fetch_optional(db)
    .await?;
    Ok(match row {
        None => Invitation::Unknown,
        Some(row) if row.consumed_at.is_some() => Invitation::Used,
        Some(row) if row.expires_at <= now => Invitation::Expired,
        Some(row) => Invitation::Valid { id: row.invitation_id, account: row.account },
    })
}

/// Consomme l'invitation et active le compte ; `false` si elle a été utilisée entre-temps.
pub async fn accept_invitation(db: &mut PgConnection, invitation: Uuid, account: Uuid, now: DateTime<Utc>) -> sqlx::Result<bool> {
    let used = sqlx::query("UPDATE invitations SET consumed_at = $2 WHERE id = $1 AND consumed_at IS NULL AND expires_at > $2")
        .bind(invitation)
        .bind(now)
        .execute(&mut *db)
        .await?;
    if used.rows_affected() != 1 {
        return Ok(false);
    }
    sqlx::query("UPDATE accounts SET status = 'active', activated_at = $2 WHERE id = $1")
        .bind(account)
        .bind(now)
        .execute(&mut *db)
        .await?;
    Ok(true)
}
