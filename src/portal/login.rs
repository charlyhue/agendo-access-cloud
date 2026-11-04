//! Connexion : page, code de secours par e-mail, déconnexion. Les passkeys sont dans
//! `webauthn.rs`.

use askama::Template;
use axum::{
    Form,
    extract::State,
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Redirect, Response},
};
use serde::Deserialize;
use serde_json::json;

use super::{PortalError, allow_ip, render, session};
use crate::{
    AppState,
    db::{accounts, audit, auth, rate_limit},
    mail,
    net::ClientIp,
};

#[derive(Template)]
#[template(path = "connexion.html")]
struct LoginPage<'a> {
    connected: bool,
    error: Option<&'a str>,
}

#[derive(Template)]
#[template(path = "code.html")]
struct CodePage<'a> {
    connected: bool,
    email: &'a str,
    error: Option<&'a str>,
}

pub async fn page() -> Response {
    render(&LoginPage { connected: false, error: None }).into_response()
}

#[derive(Deserialize)]
pub struct EmailForm {
    email: String,
}

/// Envoie un code si un compte actif correspond ; la réponse est la même sinon, pour ne pas
/// révéler quelles adresses ont un compte.
pub async fn send_code(State(state): State<AppState>, ip: ClientIp, Form(form): Form<EmailForm>) -> Result<Response, PortalError> {
    allow_ip(&state, &ip).await?;
    let Some(email) = accounts::normalize_email(&form.email) else {
        let page = LoginPage { connected: false, error: Some("Adresse e-mail invalide.") };
        return Ok((StatusCode::BAD_REQUEST, render(&page)).into_response());
    };
    let now = state.clock.now();
    if let Some(account) = accounts::by_email(&state.db, &email).await?.filter(|a| a.is_active()) {
        let limit = state.config.limits.email_codes_per_hour;
        let key = format!("code:{}", account.id);
        if rate_limit::hit(&state.db, &key, chrono::Duration::hours(1), limit, now).await? {
            let code = auth::create_email_code(&state.db, account.id, now).await?;
            // Envoi en tâche de fond : attendre Resend allongerait la réponse pour les seuls
            // comptes existants, et son délai les révélerait.
            let (mailer, mail, account) = (state.mailer.clone(), mail::login_code(&email, &code), account.id);
            tokio::spawn(async move {
                if let Err(e) = mailer.send(mail).await {
                    tracing::error!(compte = %account, erreur = %format!("{e:#}"), "code de connexion non envoyé");
                }
            });
        } else {
            tracing::warn!(compte = %account.id, "codes de connexion : limite horaire atteinte");
        }
    }
    Ok(render(&CodePage { connected: false, email: &email, error: None }).into_response())
}

#[derive(Deserialize)]
pub struct CodeForm {
    email: String,
    code: String,
}

pub async fn verify_code(
    State(state): State<AppState>,
    ip: ClientIp,
    headers: HeaderMap,
    Form(form): Form<CodeForm>,
) -> Result<Response, PortalError> {
    allow_ip(&state, &ip).await?;
    let email = accounts::normalize_email(&form.email).unwrap_or_default();
    let code: String = form.code.chars().filter(|c| !c.is_whitespace()).collect();
    let now = state.clock.now();
    let account = accounts::by_email(&state.db, &email).await?.filter(|a| a.is_active());
    let valid = match &account {
        Some(account) if code.len() == 6 => auth::check_email_code(&state.db, account.id, &code, now).await?,
        _ => false,
    };
    let Some(account) = account.filter(|_| valid) else {
        let page = CodePage { connected: false, email: &email, error: Some("Code incorrect ou expiré.") };
        return Ok((StatusCode::UNAUTHORIZED, render(&page)).into_response());
    };
    let token = auth::create_session(&state.db, account.id, session::user_agent(&headers), now).await?;
    audit::record(&state.db, now, "login_code", Some(account.id), None, json!({})).await?;
    tracing::info!(compte = %account.id, "connexion par code e-mail");
    Ok(([(header::SET_COOKIE, session::set_cookie(&token))], Redirect::to("/maisons")).into_response())
}

pub async fn logout(State(state): State<AppState>, current: session::CurrentAccount) -> Result<Response, PortalError> {
    auth::revoke_session(&state.db, current.account_id, current.session_id, state.clock.now()).await?;
    Ok(([(header::SET_COOKIE, session::clear_cookie())], Redirect::to("/connexion")).into_response())
}
