//! API des maisons (`api.DOMAINE`) : rattachement, jetons, ACME, clés de confiance.
//!
//! Tout refus porte un corps [`Refusal`] du protocole, que la maison montre à la personne.

pub mod enroll;

use agendo_access_protocol::api::{ENROLL_PATH, KEYS_PATH, KeysResponse, Refusal, RefusalReason};
use axum::{
    Json, Router,
    extract::State,
    http::{StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};

use crate::AppState;

pub fn routes() -> Router<AppState> {
    Router::new().route(KEYS_PATH, get(keys)).route(ENROLL_PATH, post(enroll::enroll))
}

/// Clés publiques de confiance du plan de contrôle.
async fn keys(State(state): State<AppState>) -> Response {
    (
        [(header::CACHE_CONTROL, "public, max-age=300")],
        Json(KeysResponse { keys: state.signer.trusted() }),
    )
        .into_response()
}

/// Refus de l'API, avec le statut HTTP de sa raison.
#[derive(Debug)]
pub struct ApiError {
    pub refusal: Refusal,
}

impl ApiError {
    pub fn new(reason: RefusalReason, detail: impl Into<String>) -> Self {
        let detail = detail.into();
        Self { refusal: Refusal { reason, detail: (!detail.is_empty()).then_some(detail) } }
    }

    pub fn status(&self) -> StatusCode {
        match self.refusal.reason {
            RefusalReason::SubscriptionInactive | RefusalReason::Revoked => StatusCode::FORBIDDEN,
            RefusalReason::BadSignature => StatusCode::UNAUTHORIZED,
            RefusalReason::RateLimited => StatusCode::TOO_MANY_REQUESTS,
            RefusalReason::InvalidCode | RefusalReason::BadRequest => StatusCode::BAD_REQUEST,
            RefusalReason::Unknown => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

impl<E: Into<anyhow::Error>> From<E> for ApiError {
    fn from(e: E) -> Self {
        tracing::error!(erreur = %format!("{:#}", e.into()), "erreur interne de l'API des maisons");
        Self::new(RefusalReason::Unknown, "erreur interne du plan de contrôle")
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.status(), Json(self.refusal)).into_response()
    }
}
