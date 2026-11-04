//! Page « Maisons » : liste, rattachement par code, révocation.

use askama::Template;
use axum::{
    extract::{Path, State, rejection::PathRejection},
    http::StatusCode,
    response::{IntoResponse, Redirect, Response},
};
use serde_json::json;
use uuid::Uuid;

use super::{PortalError, account::{date, optional_date}, render, session::CurrentAccount};
use crate::{
    AppState,
    db::{accounts, audit, houses},
};

struct HouseRow {
    id: Uuid,
    name: String,
    host: String,
    enrolled: String,
    last_token: String,
    revoked: Option<String>,
}

#[derive(Template)]
#[template(path = "maisons.html")]
struct HousesPage {
    connected: bool,
    subscription_active: bool,
    houses: Vec<HouseRow>,
}

#[derive(Template)]
#[template(path = "rattacher.html")]
struct EnrollPage {
    connected: bool,
    code: String,
    expires: String,
}

pub async fn page(State(state): State<AppState>, current: CurrentAccount) -> Result<Response, PortalError> {
    let Some(account) = accounts::by_id(&state.db, current.account_id).await? else {
        return Ok(Redirect::to("/connexion").into_response());
    };
    let houses = houses::of_account(&state.db, account.id)
        .await?
        .into_iter()
        .map(|h| HouseRow {
            id: h.id,
            name: h.name,
            host: h.host,
            enrolled: date(h.enrolled_at),
            last_token: optional_date(h.last_token_at),
            revoked: h.revoked_at.map(date),
        })
        .collect();
    Ok(render(&HousesPage { connected: true, subscription_active: account.subscription_active, houses }).into_response())
}

/// Affiche un code de rattachement à saisir dans l'interface de la maison.
pub async fn new_code(State(state): State<AppState>, current: CurrentAccount) -> Result<Response, PortalError> {
    let account = accounts::by_id(&state.db, current.account_id).await?;
    if !account.is_some_and(|a| a.subscription_active) {
        return Err(PortalError::page(
            StatusCode::FORBIDDEN,
            "Abonnement inactif",
            "L'abonnement de ce compte n'est pas actif : impossible de rattacher une maison.",
        ));
    }
    let now = state.clock.now();
    let (code, expires) = houses::create_enrollment_code(&state.db, current.account_id, now).await?;
    audit::record(&state.db, now, "enrollment_code_created", Some(current.account_id), None, json!({})).await?;
    let code = format!("{}-{}", &code[..4], &code[4..]);
    Ok(render(&EnrollPage { connected: true, code, expires: date(expires) }).into_response())
}

pub async fn revoke(
    State(state): State<AppState>,
    current: CurrentAccount,
    id: Result<Path<Uuid>, PathRejection>,
) -> Result<Response, PortalError> {
    let not_found =
        || PortalError::page(StatusCode::NOT_FOUND, "Maison introuvable", "Cette maison n'est pas rattachée à votre compte, ou déjà révoquée.");
    let Ok(Path(id)) = id else { return Err(not_found()) };
    let now = state.clock.now();
    if !houses::revoke(&state.db, id, Some(current.account_id), now).await? {
        return Err(not_found());
    }
    audit::record(&state.db, now, "house_revoked", Some(current.account_id), Some(id), json!({ "by": "account" })).await?;
    tracing::info!(compte = %current.account_id, maison = %id, "maison révoquée depuis le portail");
    Ok(Redirect::to("/maisons").into_response())
}
