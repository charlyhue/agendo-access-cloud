//! Sessions du portail : jeton opaque en cookie, haché en base.

use axum::{
    extract::FromRequestParts,
    http::{HeaderMap, HeaderValue, header, request::Parts},
    response::{IntoResponse, Redirect, Response},
};
use uuid::Uuid;

use crate::{AppState, db::auth};

/// Nom du cookie de session (`__Host-` : `Secure`, `Path=/`, sans `Domain`).
pub const COOKIE: &str = "__Host-agendo-session";

/// `Set-Cookie` d'une nouvelle session (30 jours).
pub fn set_cookie(token: &str) -> HeaderValue {
    let max_age = auth::SESSION_TTL.num_seconds();
    HeaderValue::from_str(&format!("{COOKIE}={token}; Path=/; Max-Age={max_age}; Secure; HttpOnly; SameSite=Lax"))
        .unwrap_or_else(|_| clear_cookie())
}

/// `Set-Cookie` qui efface la session.
pub fn clear_cookie() -> HeaderValue {
    HeaderValue::from_static("__Host-agendo-session=; Path=/; Max-Age=0; Secure; HttpOnly; SameSite=Lax")
}

/// Jeton de session présenté par le navigateur.
pub fn token(headers: &HeaderMap) -> Option<&str> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .find_map(|c| c.trim().strip_prefix(COOKIE)?.strip_prefix('='))
        .filter(|t| !t.is_empty())
}

/// Agent utilisateur, pour la liste des sessions.
pub fn user_agent(headers: &HeaderMap) -> &str {
    headers.get(header::USER_AGENT).and_then(|v| v.to_str().ok()).unwrap_or("")
}

/// Personne connectée ; sans session valide, redirection vers `/connexion`.
#[derive(Debug, Clone)]
pub struct CurrentAccount {
    pub account_id: Uuid,
    pub session_id: Uuid,
    pub email: String,
}

impl FromRequestParts<AppState> for CurrentAccount {
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Response> {
        let to_login = || Redirect::to("/connexion").into_response();
        let Some(token) = token(&parts.headers) else { return Err(to_login()) };
        match auth::session_by_token(&state.db, token, state.clock.now()).await {
            Ok(Some(s)) => Ok(Self { account_id: s.account_id, session_id: s.id, email: s.email }),
            Ok(None) => Err(to_login()),
            Err(e) => Err(super::PortalError::from(e).into_response()),
        }
    }
}
