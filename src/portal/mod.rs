//! Portail des personnes (`compte.DOMAINE`), rendu côté serveur.
//!
//! Pas de SPA : des pages HTML (askama, échappement automatique) et un seul script, celui de
//! WebAuthn. Toute requête qui n'est pas un GET doit venir de l'origine du portail (défense
//! CSRF en plus du cookie `SameSite=Lax`).

pub mod account;
pub mod houses;
pub mod login;
pub mod session;
pub mod webauthn;

use askama::Template;
use axum::{
    Router,
    extract::{Request, State},
    http::{HeaderValue, Method, StatusCode, header},
    middleware::{self, Next},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
};

use crate::{AppState, db::rate_limit, net::ClientIp};

pub fn routes(state: AppState) -> Router<AppState> {
    Router::new()
        .route("/", get(|| async { Redirect::to("/maisons") }))
        .route("/connexion", get(login::page))
        .route("/connexion/code", post(login::send_code))
        .route("/connexion/code/verifier", post(login::verify_code))
        .route("/connexion/passkey/options", post(webauthn::login_options))
        .route("/connexion/passkey/terminer", post(webauthn::login_finish))
        .route("/invitation/{token}", get(webauthn::invitation_page))
        .route("/invitation/{token}/options", post(webauthn::invitation_options))
        .route("/invitation/{token}/terminer", post(webauthn::invitation_finish))
        .route("/compte", get(account::page))
        .route("/compte/export", get(account::export))
        .route("/compte/supprimer", post(account::delete))
        .route("/compte/sessions/{id}/revoquer", post(account::revoke_session))
        .route("/compte/passkeys/options", post(webauthn::account_options))
        .route("/compte/passkeys/terminer", post(webauthn::account_finish))
        .route("/compte/passkeys/{id}/retirer", post(webauthn::remove))
        .route("/deconnexion", post(login::logout))
        .route("/maisons", get(houses::page))
        .route("/maisons/rattacher", post(houses::new_code))
        .route("/maisons/{id}/revoquer", post(houses::revoke))
        .route("/static/portail.css", get(css))
        .route("/static/webauthn.js", get(webauthn::script))
        .route("/static/favicon.svg", get(favicon))
        .layer(middleware::from_fn_with_state(state, check_origin))
        .layer(middleware::from_fn(security_headers))
}

async fn css() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/css; charset=utf-8"), (header::CACHE_CONTROL, "no-cache")],
        include_str!("../../static/portail.css"),
    )
}

/// Icône du portail : le logo de l'interface des maisons (servi d'ici, pas en `data:`, que la
/// CSP refuse).
async fn favicon() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "image/svg+xml"), (header::CACHE_CONTROL, "public, max-age=86400")],
        include_str!("../../static/favicon.svg"),
    )
}

/// En-têtes de sécurité de toutes les pages.
async fn security_headers(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    let set = |headers: &mut axum::http::HeaderMap, name, value: &'static str| {
        headers.entry(name).or_insert(HeaderValue::from_static(value));
    };
    set(
        headers,
        header::CONTENT_SECURITY_POLICY,
        "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; \
         form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
    );
    set(headers, header::X_CONTENT_TYPE_OPTIONS, "nosniff");
    // `same-origin` et non `no-referrer` : avec `no-referrer`, le navigateur envoie
    // `Origin: null` sur les formulaires (standard Fetch), que `check_origin` refuserait. Aucune
    // ressource tierce n'est chargée : le jeton d'une URL d'invitation ne sort pas du portail.
    set(headers, header::REFERRER_POLICY, "same-origin");
    set(headers, header::CACHE_CONTROL, "no-store");
    set(headers, header::X_FRAME_OPTIONS, "DENY");
    response
}

/// Refuse toute requête non GET dont l'`Origin` n'est pas celle du portail.
async fn check_origin(State(state): State<AppState>, request: Request, next: Next) -> Response {
    if request.method() != Method::GET && request.method() != Method::HEAD {
        let origin = request.headers().get(header::ORIGIN).and_then(|v| v.to_str().ok());
        if origin != Some(state.config.portal_origin().as_str()) {
            return PortalError::page(StatusCode::FORBIDDEN, "Requête refusée", "Cette requête ne vient pas du portail.")
                .into_response();
        }
    }
    next.run(request).await
}

#[derive(Template)]
#[template(path = "erreur.html")]
struct ErrorPage<'a> {
    connected: bool,
    title: &'a str,
    message: &'a str,
}

/// Erreur rendue en page HTML, en français. Une erreur interne est journalisée et la page ne
/// dit rien de plus.
#[derive(Debug)]
pub enum PortalError {
    Page { status: StatusCode, title: &'static str, message: String },
    Internal(anyhow::Error),
}

impl PortalError {
    pub fn page(status: StatusCode, title: &'static str, message: impl Into<String>) -> Self {
        Self::Page { status, title, message: message.into() }
    }

    pub fn rate_limited() -> Self {
        Self::page(StatusCode::TOO_MANY_REQUESTS, "Trop de tentatives", "Trop de tentatives : réessayez dans une minute.")
    }
}

impl<E: Into<anyhow::Error>> From<E> for PortalError {
    fn from(e: E) -> Self {
        Self::Internal(e.into())
    }
}

impl IntoResponse for PortalError {
    fn into_response(self) -> Response {
        let (status, title, message) = match self {
            PortalError::Page { status, title, message } => (status, title, message),
            PortalError::Internal(e) => {
                tracing::error!(erreur = %format!("{e:#}"), "erreur interne du portail");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Erreur interne",
                    "Une erreur interne est survenue. Réessayez plus tard.".to_owned(),
                )
            }
        };
        let page = ErrorPage { connected: false, title, message: &message };
        (status, render(&page)).into_response()
    }
}

/// Page HTML ; une erreur de gabarit (impossible en pratique) devient une page brute.
pub fn render(template: &impl Template) -> Html<String> {
    Html(template.render().unwrap_or_else(|e| {
        tracing::error!(erreur = %e, "gabarit invalide");
        "Erreur interne".into()
    }))
}

/// Cérémonie du portail permise pour cette IP (limite par minute) ?
pub async fn allow_ip(state: &AppState, ip: &ClientIp) -> Result<(), PortalError> {
    let allowed = rate_limit::hit(
        &state.db,
        &format!("portail:{}", ip.0),
        chrono::Duration::minutes(1),
        state.config.limits.ip_per_minute,
        state.clock.now(),
    )
    .await?;
    if allowed { Ok(()) } else { Err(PortalError::rate_limited()) }
}
