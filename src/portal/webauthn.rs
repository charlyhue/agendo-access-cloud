//! Cérémonies WebAuthn du portail : passkey créée par le lien d'invitation, connexion,
//! ajout et retrait de passkeys depuis le compte.
//!
//! Chaque cérémonie tient en deux requêtes JSON (`…/options`, `…/terminer`), appelées par
//! `static/webauthn.js`. Le défi est rangé en base (usage unique, 5 minutes) et lié à son
//! usage, et selon le cas à l'invitation ou au compte. La vérification est celle du socle
//! (`agendo-webauthn`) : RP ID = hôte du portail, origine = celle du portail, vérification
//! de l'utilisateur obligatoire.

use agendo_webauthn::{ALGORITHMS, AssertionCredential, Expected, RegistrationCredential, b64, challenge_of, unb64};
use askama::Template;
use axum::{
    Json,
    extract::{Path, State, rejection::JsonRejection, rejection::PathRejection},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Redirect, Response},
};
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

use super::{PortalError, render, session};
use crate::{
    AppState,
    db::{
        accounts::{self, Account, Invitation},
        audit,
        auth::{self, Challenge, Passkey, Purpose, Removal},
        rate_limit,
    },
    net::ClientIp,
};

/// Délai laissé au navigateur (ms), aligné sur la validité du défi.
const TIMEOUT_MS: i64 = 5 * 60 * 1000;

/// Erreur d'une cérémonie, rendue en JSON `{ "error": … }` pour le script.
#[derive(Debug)]
pub struct JsonError(StatusCode, String);

impl JsonError {
    fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Self(status, message.into())
    }
}

impl<E: Into<anyhow::Error>> From<E> for JsonError {
    fn from(e: E) -> Self {
        tracing::error!(erreur = %format!("{:#}", e.into()), "erreur interne d'une cérémonie WebAuthn");
        Self(StatusCode::INTERNAL_SERVER_ERROR, "Erreur interne : réessayez plus tard.".into())
    }
}

impl IntoResponse for JsonError {
    fn into_response(self) -> Response {
        (self.0, Json(json!({ "error": self.1 }))).into_response()
    }
}

type JsonResult = Result<Response, JsonError>;

async fn allow_ip(state: &AppState, ip: &ClientIp) -> Result<(), JsonError> {
    let allowed = rate_limit::hit(
        &state.db,
        &format!("portail:{}", ip.0),
        chrono::Duration::minutes(1),
        state.config.limits.ip_per_minute,
        state.clock.now(),
    )
    .await?;
    if allowed { Ok(()) } else { Err(JsonError::new(StatusCode::TOO_MANY_REQUESTS, "Trop de tentatives : réessayez dans une minute.")) }
}

fn body<T>(body: Result<Json<T>, JsonRejection>) -> Result<T, JsonError> {
    body.map(|Json(b)| b).map_err(|_| JsonError::new(StatusCode::BAD_REQUEST, "Réponse du navigateur illisible."))
}

/// Options de `navigator.credentials.create()`, en base64url.
fn creation_options(state: &AppState, account: &Account, challenge: &[u8], existing: &[Passkey]) -> Value {
    json!({
        "challenge": b64(challenge),
        "rp": { "id": state.config.rp_id(), "name": "Agendo Access" },
        "user": { "id": b64(&account.webauthn_user_id), "name": account.email, "displayName": account.email },
        "pubKeyCredParams": ALGORITHMS.iter().map(|alg| json!({ "type": "public-key", "alg": alg })).collect::<Vec<_>>(),
        "authenticatorSelection": { "residentKey": "required", "requireResidentKey": true, "userVerification": "required" },
        "attestation": "none",
        "timeout": TIMEOUT_MS,
        "excludeCredentials": existing.iter().map(|p| json!({ "type": "public-key", "id": b64(&p.credential_id) })).collect::<Vec<_>>(),
    })
}

/// Nom donné à une passkey : blancs retirés, sans caractère de contrôle, 64 caractères au plus.
fn passkey_name(input: &str) -> String {
    let name: String = input.trim().chars().filter(|c| !c.is_control()).take(64).collect();
    if name.is_empty() { "Passkey".into() } else { name }
}

/// Défi annoncé par la réponse du navigateur.
fn announced_challenge(client_data_json: &str) -> Result<Vec<u8>, JsonError> {
    challenge_of(client_data_json).map_err(|_| JsonError::new(StatusCode::BAD_REQUEST, "Réponse du navigateur illisible."))
}

/// Vérifie un enregistrement contre le défi attendu.
fn verify_registration(
    state: &AppState,
    credential: &RegistrationCredential,
    challenge: &[u8],
) -> Result<agendo_webauthn::NewCredential, JsonError> {
    let origin = state.config.portal_origin();
    let expected = Expected { rp_id: state.config.rp_id(), origin: &origin, challenge };
    agendo_webauthn::verify_registration(credential, &expected).map_err(|reason| {
        tracing::warn!(raison = %reason, "enregistrement de passkey refusé");
        JsonError::new(StatusCode::BAD_REQUEST, "Passkey refusée par le portail : recommencez.")
    })
}

fn signed_in(token: &str, redirect: &str) -> Response {
    ([(header::SET_COOKIE, session::set_cookie(token))], Json(json!({ "redirect": redirect }))).into_response()
}

// --- Invitation ------------------------------------------------------------------------

#[derive(Template)]
#[template(path = "invitation.html")]
struct InvitationPage<'a> {
    connected: bool,
    email: &'a str,
    token: &'a str,
}

/// Lien d'invitation : inconnu (404), expiré ou utilisé (410), ou l'invitation.
async fn lookup(state: &AppState, token: Result<Path<String>, PathRejection>) -> Result<(String, Uuid, Account), PortalError> {
    let Ok(Path(token)) = token else { return Err(unknown_invitation()) };
    match accounts::invitation(&state.db, &token, state.clock.now()).await? {
        Invitation::Valid { id, account } => Ok((token, id, account)),
        Invitation::Used => Err(PortalError::page(
            StatusCode::GONE,
            "Invitation déjà utilisée",
            "Ce lien d'invitation a déjà servi : connectez-vous, ou demandez une nouvelle invitation.",
        )),
        Invitation::Expired => Err(PortalError::page(
            StatusCode::GONE,
            "Invitation expirée",
            "Ce lien d'invitation a expiré (il vaut 7 jours) : demandez une nouvelle invitation.",
        )),
        Invitation::Unknown => Err(unknown_invitation()),
    }
}

fn unknown_invitation() -> PortalError {
    PortalError::page(StatusCode::NOT_FOUND, "Invitation inconnue", "Ce lien d'invitation n'existe pas : vérifiez qu'il est complet.")
}

impl From<PortalError> for JsonError {
    fn from(e: PortalError) -> Self {
        match e {
            PortalError::Page { status, message, .. } => JsonError(status, message),
            PortalError::Internal(e) => JsonError::from(e),
        }
    }
}

pub async fn invitation_page(State(state): State<AppState>, token: Result<Path<String>, PathRejection>) -> Result<Response, PortalError> {
    let (token, _, account) = lookup(&state, token).await?;
    Ok(render(&InvitationPage { connected: false, email: &account.email, token: &token }).into_response())
}

pub async fn invitation_options(
    State(state): State<AppState>,
    ip: ClientIp,
    token: Result<Path<String>, PathRejection>,
) -> JsonResult {
    allow_ip(&state, &ip).await?;
    let (_, invitation, account) = lookup(&state, token).await?;
    let owner = Challenge { account_id: Some(account.id), invitation_id: Some(invitation) };
    let challenge = auth::create_challenge(&state.db, Purpose::RegisterInvitation, owner, state.clock.now()).await?;
    let existing = auth::passkeys_of(&state.db, account.id).await?;
    Ok(Json(creation_options(&state, &account, &challenge, &existing)).into_response())
}

#[derive(Deserialize)]
pub struct RegisterBody {
    credential: RegistrationCredential,
    #[serde(default)]
    name: String,
}

pub async fn invitation_finish(
    State(state): State<AppState>,
    ip: ClientIp,
    headers: HeaderMap,
    token: Result<Path<String>, PathRejection>,
    request: Result<Json<RegisterBody>, JsonRejection>,
) -> JsonResult {
    allow_ip(&state, &ip).await?;
    let (_, invitation, account) = lookup(&state, token).await?;
    let request = body(request)?;
    let now = state.clock.now();
    let challenge = announced_challenge(&request.credential.response.client_data_json)?;
    // Le défi est consommé même si la suite échoue : une réponse ne sert qu'une fois.
    let owner = auth::take_challenge(&state.db, &challenge, Purpose::RegisterInvitation, now).await?;
    if owner.and_then(|o| o.invitation_id) != Some(invitation) {
        return Err(JsonError::new(StatusCode::BAD_REQUEST, "Cérémonie expirée : recommencez."));
    }
    let credential = verify_registration(&state, &request.credential, &challenge)?;

    let mut tx = state.db.begin().await?;
    if !auth::insert_passkey(&mut *tx, account.id, &credential, &passkey_name(&request.name), now).await? {
        return Err(JsonError::new(StatusCode::CONFLICT, "Cette passkey est déjà enregistrée."));
    }
    if !accounts::accept_invitation(&mut tx, invitation, account.id, now).await? {
        return Err(JsonError::new(StatusCode::GONE, "Ce lien d'invitation a déjà été utilisé."));
    }
    let token = auth::create_session(&mut *tx, account.id, session::user_agent(&headers), now).await?;
    audit::record(&mut *tx, now, "account_activated", Some(account.id), None, json!({})).await?;
    tx.commit().await?;
    tracing::info!(compte = %account.id, "compte activé par passkey");
    Ok(signed_in(&token, "/maisons"))
}

// --- Connexion ---------------------------------------------------------------------------

pub async fn login_options(State(state): State<AppState>, ip: ClientIp) -> JsonResult {
    allow_ip(&state, &ip).await?;
    let owner = Challenge { account_id: None, invitation_id: None };
    let challenge = auth::create_challenge(&state.db, Purpose::Login, owner, state.clock.now()).await?;
    // Passkeys découvrables : le navigateur propose celles du RP ID, sans liste.
    Ok(Json(json!({
        "challenge": b64(&challenge),
        "rpId": state.config.rp_id(),
        "userVerification": "required",
        "timeout": TIMEOUT_MS,
        "allowCredentials": [],
    }))
    .into_response())
}

#[derive(Deserialize)]
pub struct LoginBody {
    credential: AssertionCredential,
}

pub async fn login_finish(
    State(state): State<AppState>,
    ip: ClientIp,
    headers: HeaderMap,
    request: Result<Json<LoginBody>, JsonRejection>,
) -> JsonResult {
    allow_ip(&state, &ip).await?;
    let credential = body(request)?.credential;
    let now = state.clock.now();
    let refused = || JsonError::new(StatusCode::UNAUTHORIZED, "Connexion refusée : passkey inconnue ou cérémonie expirée.");
    let challenge = announced_challenge(&credential.response.client_data_json)?;
    if auth::take_challenge(&state.db, &challenge, Purpose::Login, now).await?.is_none() {
        return Err(refused());
    }
    let raw_id = unb64(&credential.raw_id).map_err(|_| refused())?;
    let Some(passkey) = auth::passkey_by_credential(&state.db, &raw_id).await? else { return Err(refused()) };
    let Some(account) = accounts::by_id(&state.db, passkey.account_id).await?.filter(Account::is_active) else {
        return Err(refused());
    };
    let origin = state.config.portal_origin();
    let expected = Expected { rp_id: state.config.rp_id(), origin: &origin, challenge: &challenge };
    let stored_count = u32::try_from(passkey.sign_count).unwrap_or(u32::MAX);
    let sign_count = agendo_webauthn::verify_assertion(&credential, &expected, &passkey.public_key, passkey.algorithm, stored_count)
        .map_err(|reason| {
            tracing::warn!(compte = %account.id, raison = %reason, "connexion par passkey refusée");
            refused()
        })?;
    auth::passkey_used(&state.db, passkey.id, sign_count, now).await?;
    let token = auth::create_session(&state.db, account.id, session::user_agent(&headers), now).await?;
    audit::record(&state.db, now, "login_passkey", Some(account.id), None, json!({})).await?;
    tracing::info!(compte = %account.id, "connexion par passkey");
    Ok(signed_in(&token, "/maisons"))
}

// --- Compte : ajout et retrait -----------------------------------------------------------

pub async fn account_options(State(state): State<AppState>, current: session::CurrentAccount) -> JsonResult {
    let Some(account) = accounts::by_id(&state.db, current.account_id).await? else {
        return Err(JsonError::new(StatusCode::UNAUTHORIZED, "Session expirée."));
    };
    let owner = Challenge { account_id: Some(account.id), invitation_id: None };
    let challenge = auth::create_challenge(&state.db, Purpose::RegisterAccount, owner, state.clock.now()).await?;
    let existing = auth::passkeys_of(&state.db, account.id).await?;
    Ok(Json(creation_options(&state, &account, &challenge, &existing)).into_response())
}

pub async fn account_finish(
    State(state): State<AppState>,
    current: session::CurrentAccount,
    request: Result<Json<RegisterBody>, JsonRejection>,
) -> JsonResult {
    let request = body(request)?;
    let now = state.clock.now();
    let challenge = announced_challenge(&request.credential.response.client_data_json)?;
    let owner = auth::take_challenge(&state.db, &challenge, Purpose::RegisterAccount, now).await?;
    if owner.and_then(|o| o.account_id) != Some(current.account_id) {
        return Err(JsonError::new(StatusCode::BAD_REQUEST, "Cérémonie expirée : recommencez."));
    }
    let credential = verify_registration(&state, &request.credential, &challenge)?;
    if !auth::insert_passkey(&state.db, current.account_id, &credential, &passkey_name(&request.name), now).await? {
        return Err(JsonError::new(StatusCode::CONFLICT, "Cette passkey est déjà enregistrée."));
    }
    audit::record(&state.db, now, "passkey_added", Some(current.account_id), None, json!({})).await?;
    Ok(Json(json!({ "redirect": "/compte" })).into_response())
}

pub async fn remove(
    State(state): State<AppState>,
    current: session::CurrentAccount,
    id: Result<Path<Uuid>, PathRejection>,
) -> Result<Response, PortalError> {
    let not_found = || PortalError::page(StatusCode::NOT_FOUND, "Passkey introuvable", "Cette passkey n'existe pas sur votre compte.");
    let Ok(Path(id)) = id else { return Err(not_found()) };
    match auth::remove_passkey(&state.db, current.account_id, id).await? {
        Removal::Removed => {
            audit::record(&state.db, state.clock.now(), "passkey_removed", Some(current.account_id), None, json!({})).await?;
            Ok(Redirect::to("/compte").into_response())
        }
        Removal::NotFound => Err(not_found()),
        Removal::LastOne => Err(PortalError::page(
            StatusCode::CONFLICT,
            "Dernière passkey",
            "C'est la dernière passkey du compte : ajoutez-en une autre avant de retirer celle-ci.",
        )),
    }
}

pub async fn script() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/javascript; charset=utf-8"), (header::CACHE_CONTROL, "public, max-age=3600")],
        include_str!("../../static/webauthn.js"),
    )
}
