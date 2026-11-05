//! API des maisons (`api.DOMAINE`) : rattachement, jetons, ACME, clés de confiance.
//!
//! Tout refus porte un corps [`Refusal`] du protocole, que la maison montre à la personne.

pub mod enroll;
pub mod signed;

use agendo_access_protocol::api::{ACME_PATH, ENROLL_PATH, KEYS_PATH, TOKENS_PATH, KeysResponse, Refusal, RefusalReason};
use axum::{
    Json, Router,
    extract::State,
    http::{StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};

use crate::AppState;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route(KEYS_PATH, get(keys))
        .route(ENROLL_PATH, post(enroll::enroll))
        .route(TOKENS_PATH, post(signed::tokens))
        .route(ACME_PATH, post(signed::acme_put).delete(signed::acme_delete))
}

/// Clés publiques de confiance du plan de contrôle.
async fn keys(State(state): State<AppState>) -> Response {
    (
        [(header::CACHE_CONTROL, "public, max-age=300")],
        Json(KeysResponse { keys: state.signer.trusted() }),
    )
        .into_response()
}

/// Refus de l'API, avec le statut HTTP que le protocole donne à sa raison
/// ([`RefusalReason::http_status`]). Une erreur interne n'est pas un refus : elle porte la
/// raison `unknown` mais répond en 5xx, pour que la maison réessaie plus tard au lieu de croire
/// sa requête fautive.
#[derive(Debug)]
pub struct ApiError {
    pub refusal: Refusal,
    internal: Option<StatusCode>,
}

impl ApiError {
    pub fn new(reason: RefusalReason, detail: impl Into<String>) -> Self {
        let detail = detail.into();
        Self { refusal: Refusal { reason, detail: (!detail.is_empty()).then_some(detail) }, internal: None }
    }

    /// Échec de notre côté (`status` : 500, ou 502 pour un service en amont).
    pub fn internal(status: StatusCode, detail: &str) -> Self {
        Self { internal: Some(status), ..Self::new(RefusalReason::Unknown, detail) }
    }

    pub fn status(&self) -> StatusCode {
        self.internal.unwrap_or_else(|| {
            StatusCode::from_u16(self.refusal.reason.http_status()).unwrap_or(StatusCode::BAD_REQUEST)
        })
    }
}

impl<E: Into<anyhow::Error>> From<E> for ApiError {
    fn from(e: E) -> Self {
        tracing::error!(erreur = %format!("{:#}", e.into()), "erreur interne de l'API des maisons");
        Self::internal(StatusCode::INTERNAL_SERVER_ERROR, "erreur interne du plan de contrôle")
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.status(), Json(self.refusal)).into_response()
    }
}
