//! Page « Compte » : passkeys, sessions, export des données (RGPD), suppression du compte.

use askama::Template;
use axum::{
    Form,
    extract::{Path, State, rejection::PathRejection},
    http::{StatusCode, header},
    response::{IntoResponse, Redirect, Response},
};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::json;
use uuid::Uuid;

use super::{PortalError, render, session::{self, CurrentAccount}};
use crate::{
    AppState,
    db::{accounts, audit, auth},
};

/// Date lisible des pages (UTC).
pub fn date(at: DateTime<Utc>) -> String {
    at.format("%d/%m/%Y %H:%M UTC").to_string()
}

pub fn optional_date(at: Option<DateTime<Utc>>) -> String {
    at.map(date).unwrap_or_else(|| "jamais".into())
}

struct PasskeyRow {
    id: Uuid,
    name: String,
    created: String,
    last_used: String,
}

struct SessionRow {
    id: Uuid,
    current: bool,
    user_agent: String,
    created: String,
    last_seen: String,
}

#[derive(Template)]
#[template(path = "compte.html")]
struct AccountPage {
    connected: bool,
    email: String,
    subscription_active: bool,
    passkeys: Vec<PasskeyRow>,
    sessions: Vec<SessionRow>,
}

#[derive(sqlx::FromRow)]
struct SessionInfo {
    id: Uuid,
    user_agent: String,
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    last_seen_at: DateTime<Utc>,
    revoked_at: Option<DateTime<Utc>>,
}

async fn sessions_of(state: &AppState, account: Uuid) -> sqlx::Result<Vec<SessionInfo>> {
    sqlx::query_as(
        "SELECT id, user_agent, created_at, expires_at, last_seen_at, revoked_at FROM sessions
         WHERE account_id = $1 ORDER BY last_seen_at DESC",
    )
    .bind(account)
    .fetch_all(&state.db)
    .await
}

pub async fn page(State(state): State<AppState>, current: CurrentAccount) -> Result<Response, PortalError> {
    let Some(account) = accounts::by_id(&state.db, current.account_id).await? else {
        return Ok(Redirect::to("/connexion").into_response());
    };
    let now = state.clock.now();
    let passkeys = auth::passkeys_of(&state.db, account.id)
        .await?
        .into_iter()
        .map(|p| PasskeyRow { id: p.id, name: p.name, created: date(p.created_at), last_used: optional_date(p.last_used_at) })
        .collect();
    let sessions = sessions_of(&state, account.id)
        .await?
        .into_iter()
        .filter(|s| s.revoked_at.is_none() && s.expires_at > now)
        .map(|s| SessionRow {
            id: s.id,
            current: s.id == current.session_id,
            user_agent: if s.user_agent.is_empty() { "navigateur inconnu".into() } else { s.user_agent },
            created: date(s.created_at),
            last_seen: date(s.last_seen_at),
        })
        .collect();
    let page = AccountPage {
        connected: true,
        email: account.email,
        subscription_active: account.subscription_active,
        passkeys,
        sessions,
    };
    Ok(render(&page).into_response())
}

pub async fn revoke_session(
    State(state): State<AppState>,
    current: CurrentAccount,
    id: Result<Path<Uuid>, PathRejection>,
) -> Result<Response, PortalError> {
    let not_found = || PortalError::page(StatusCode::NOT_FOUND, "Session introuvable", "Cette session n'existe pas sur votre compte.");
    let Ok(Path(id)) = id else { return Err(not_found()) };
    let now = state.clock.now();
    if !auth::revoke_session(&state.db, current.account_id, id, now).await? {
        return Err(not_found());
    }
    audit::record(&state.db, now, "session_revoked", Some(current.account_id), None, json!({})).await?;
    Ok(Redirect::to("/compte").into_response())
}

/// Export JSON de tout ce que le service garde sur le compte, sans secret ni clé.
pub async fn export(State(state): State<AppState>, current: CurrentAccount) -> Result<Response, PortalError> {
    let Some(account) = accounts::by_id(&state.db, current.account_id).await? else {
        return Ok(Redirect::to("/connexion").into_response());
    };
    let now = state.clock.now();
    let passkeys: Vec<_> = auth::passkeys_of(&state.db, account.id)
        .await?
        .into_iter()
        .map(|p| json!({ "nom": p.name, "creee_le": p.created_at, "derniere_utilisation": p.last_used_at, "synchronisable": p.backup_eligible }))
        .collect();
    let sessions: Vec<_> = sessions_of(&state, account.id)
        .await?
        .into_iter()
        .map(|s| json!({ "navigateur": s.user_agent, "creee_le": s.created_at, "expire_le": s.expires_at,
                         "derniere_activite": s.last_seen_at, "revoquee_le": s.revoked_at }))
        .collect();
    let houses: Vec<(String, String, DateTime<Utc>, Option<DateTime<Utc>>, Option<DateTime<Utc>>)> = sqlx::query_as(
        "SELECT name, host, enrolled_at, revoked_at, last_token_at FROM houses WHERE account_id = $1 ORDER BY enrolled_at",
    )
    .bind(account.id)
    .fetch_all(&state.db)
    .await?;
    let houses: Vec<_> = houses
        .into_iter()
        .map(|(name, host, enrolled, revoked, last)| json!({ "nom": name, "nom_hote": host, "rattachee_le": enrolled,
                                                             "revoquee_le": revoked, "dernier_jeton_le": last }))
        .collect();
    let journal: Vec<(DateTime<Utc>, String, serde_json::Value)> =
        sqlx::query_as("SELECT at, event, detail FROM audit WHERE account_id = $1 ORDER BY id")
            .bind(account.id)
            .fetch_all(&state.db)
            .await?;
    let journal: Vec<_> =
        journal.into_iter().map(|(at, event, detail)| json!({ "date": at, "evenement": event, "detail": detail })).collect();
    let data = json!({
        "exporte_le": now,
        "compte": {
            "email": account.email,
            "statut": account.status,
            "abonnement": { "actif": account.subscription_active, "source": account.subscription_source },
            "cree_le": account.created_at,
            "active_le": account.activated_at,
        },
        "passkeys": passkeys,
        "sessions": sessions,
        "maisons": houses,
        "journal": journal,
    });
    audit::record(&state.db, now, "data_exported", Some(account.id), None, json!({})).await?;
    let body = serde_json::to_vec_pretty(&data)?;
    Ok((
        [
            (header::CONTENT_TYPE, "application/json; charset=utf-8"),
            (header::CONTENT_DISPOSITION, "attachment; filename=\"agendo-access-compte.json\""),
        ],
        body,
    )
        .into_response())
}

#[derive(Deserialize)]
pub struct DeleteForm {
    confirmation: String,
}

/// Supprime le compte. Ses maisons sont révoquées et détachées (nom effacé) : la ligne reste
/// pour que leur nom d'hôte ne soit jamais réattribué.
pub async fn delete(
    State(state): State<AppState>,
    current: CurrentAccount,
    Form(form): Form<DeleteForm>,
) -> Result<Response, PortalError> {
    if accounts::normalize_email(&form.confirmation).as_deref() != Some(current.email.as_str()) {
        return Err(PortalError::page(
            StatusCode::BAD_REQUEST,
            "Suppression non confirmée",
            "Saisissez exactement l'adresse e-mail du compte pour confirmer sa suppression.",
        ));
    }
    let now = state.clock.now();
    let mut tx = state.db.begin().await?;
    let houses: Vec<Uuid> = sqlx::query_scalar(
        "UPDATE houses SET revoked_at = COALESCE(revoked_at, $2), account_id = NULL, name = '' WHERE account_id = $1 RETURNING id",
    )
    .bind(current.account_id)
    .bind(now)
    .fetch_all(&mut *tx)
    .await?;
    for house in &houses {
        audit::record(&mut *tx, now, "house_revoked", None, Some(*house), json!({"by": "account_deletion"})).await?;
    }
    sqlx::query("DELETE FROM accounts WHERE id = $1").bind(current.account_id).execute(&mut *tx).await?;
    audit::record(&mut *tx, now, "account_deleted", None, None, json!({ "houses": houses.len() })).await?;
    tx.commit().await?;
    tracing::info!(compte = %current.account_id, maisons = houses.len(), "compte supprimé");
    Ok(([(header::SET_COOKIE, session::clear_cookie())], Redirect::to("/connexion")).into_response())
}
