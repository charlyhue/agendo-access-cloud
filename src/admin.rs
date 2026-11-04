//! Commandes d'administration, lancées dans le conteneur (`agendo-access-cloud admin …`).
//!
//! Pas d'interface d'administration en V1 : rien d'exposé. Chaque commande rend le texte à
//! afficher, pour être testée sans terminal.

use anyhow::{Context, bail};
use serde_json::json;

use crate::{
    AppState,
    db::{accounts, audit, houses},
    mail,
};

fn email_arg(input: &str) -> anyhow::Result<String> {
    accounts::normalize_email(input).with_context(|| format!("{input:?} n'est pas une adresse e-mail"))
}

async fn existing(state: &AppState, input: &str) -> anyhow::Result<accounts::Account> {
    let email = email_arg(input)?;
    accounts::by_email(&state.db, &email).await?.with_context(|| format!("aucun compte pour {email}"))
}

/// Invite une personne : compte `invited` (abonnement actif, source `manual`) et lien à usage
/// unique par e-mail. Pour un compte encore `invited`, envoie une nouvelle invitation.
pub async fn invite(state: &AppState, input: &str) -> anyhow::Result<String> {
    let email = email_arg(input)?;
    let now = state.clock.now();
    let mut tx = state.db.begin().await?;
    let account = match accounts::by_email(&mut *tx, &email).await? {
        Some(account) if account.is_active() => bail!("le compte {email} est déjà actif"),
        Some(account) => account,
        None => accounts::create_invited(&mut *tx, &email, now).await?,
    };
    let token = accounts::create_invitation(&mut tx, account.id, now).await?;
    audit::record(&mut *tx, now, "invitation_sent", Some(account.id), None, json!({"by": "admin"})).await?;
    tx.commit().await?;

    let link = state.config.portal_link(&format!("/invitation/{token}"));
    state
        .mailer
        .send(mail::invitation(&email, &link))
        .await
        .with_context(|| format!("invitation créée mais e-mail non envoyé à {email} : relancer la commande"))?;
    tracing::info!(compte = %account.id, "invitation envoyée");
    Ok(format!("Invitation envoyée à {email} (valable 7 jours)."))
}

/// Liste des comptes : e-mail, état, abonnement, maisons rattachées.
pub async fn list(state: &AppState) -> anyhow::Result<String> {
    let rows: Vec<(String, String, bool, i64, chrono::DateTime<chrono::Utc>)> = sqlx::query_as(
        "SELECT a.email, a.status, a.subscription_active,
                (SELECT count(*) FROM houses h WHERE h.account_id = a.id AND h.revoked_at IS NULL),
                a.created_at
         FROM accounts a ORDER BY a.created_at, a.email",
    )
    .fetch_all(&state.db)
    .await?;
    if rows.is_empty() {
        return Ok("aucun compte".into());
    }
    let width = rows.iter().map(|r| r.0.chars().count()).max().unwrap_or(0).max(6);
    let mut out = format!("{:width$}  {:7}  {:10}  {:>7}  créé le\n", "e-mail", "état", "abonnement", "maisons");
    for (email, status, active, houses, created) in rows {
        let status = if status == "active" { "actif" } else { "invité" };
        let subscription = if active { "actif" } else { "suspendu" };
        out.push_str(&format!(
            "{email:width$}  {status:7}  {subscription:10}  {houses:>7}  {}\n",
            created.format("%Y-%m-%d")
        ));
    }
    Ok(out)
}

async fn set_subscription(state: &AppState, input: &str, active: bool) -> anyhow::Result<String> {
    let account = existing(state, input).await?;
    let now = state.clock.now();
    let mut tx = state.db.begin().await?;
    accounts::set_subscription(&mut *tx, account.id, active).await?;
    let event = if active { "subscription_resumed" } else { "subscription_suspended" };
    audit::record(&mut *tx, now, event, Some(account.id), None, json!({"by": "admin"})).await?;
    tx.commit().await?;
    tracing::info!(compte = %account.id, actif = active, "abonnement modifié");
    Ok(if active {
        format!("Abonnement rétabli pour {}.", account.email)
    } else {
        format!("Abonnement suspendu pour {} : ses maisons ne reçoivent plus de jetons.", account.email)
    })
}

/// Suspend l'abonnement : les maisons du compte se voient refuser leurs jetons
/// (`subscription_inactive`). Le portail reste ouvert (export, suppression).
pub async fn suspend(state: &AppState, email: &str) -> anyhow::Result<String> {
    set_subscription(state, email, false).await
}

pub async fn resume(state: &AppState, email: &str) -> anyhow::Result<String> {
    set_subscription(state, email, true).await
}

/// Révoque une maison, par nom d'hôte complet ou par étiquette : ses jetons ne sont plus
/// renouvelés (`revoked`), son nom d'hôte n'est jamais réattribué.
pub async fn revoke_house(state: &AppState, host_or_label: &str) -> anyhow::Result<String> {
    let value = host_or_label.trim().trim_end_matches('.').to_ascii_lowercase();
    let house = houses::by_host_or_label(&state.db, &value).await?.with_context(|| format!("aucune maison {value}"))?;
    if house.revoked_at.is_some() {
        return Ok(format!("La maison {} est déjà révoquée.", house.host));
    }
    let now = state.clock.now();
    let mut tx = state.db.begin().await?;
    houses::revoke(&mut *tx, house.id, None, now).await?;
    audit::record(&mut *tx, now, "house_revoked", house.account_id, Some(house.id), json!({"by": "admin"})).await?;
    tx.commit().await?;
    tracing::info!(maison = %house.id, hote = %house.host, "maison révoquée par l'administration");
    Ok(format!("Maison {} révoquée.", house.host))
}
