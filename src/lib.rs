//! Plan de contrôle et portail d'Agendo Access.
//!
//! Un seul serveur axum : l'API des maisons (`/v1/*`, `/.well-known/agendo-access/*`) et le
//! portail (tout le reste). Sans état hors de PostgreSQL : deux instances peuvent tourner.

pub mod admin;
pub mod api;
pub mod clock;
pub mod config;
pub mod crypto;
pub mod db;
pub mod dns;
pub mod http;
pub mod mail;
pub mod net;
pub mod portal;
pub mod signing;
pub mod state;

use std::time::Instant;

use axum::{
    Router,
    extract::{MatchedPath, Request, State},
    http::StatusCode,
    middleware::{self, Next},
    response::Response,
    routing::get,
};

pub use state::AppState;

/// Migrations du schéma (`migrations/`), appliquées au démarrage de `serve` et par `migrate`.
pub static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!();

pub fn app(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(health))
        .merge(api::routes())
        .merge(portal::routes(state.clone()))
        .route_layer(middleware::from_fn(log_request))
        .with_state(state)
}

/// Vivacité : répond si la base répond.
async fn health(State(state): State<AppState>) -> Result<&'static str, StatusCode> {
    sqlx::query("SELECT 1").execute(&state.db).await.map_err(|e| {
        tracing::error!(erreur = %e, "base injoignable");
        StatusCode::SERVICE_UNAVAILABLE
    })?;
    Ok("ok")
}

/// Journal des requêtes : la route (`/invitation/{token}`), jamais l'URI, qui peut porter un
/// secret (lien d'invitation) ; ni requête, ni corps, ni en-tête.
async fn log_request(request: Request, next: Next) -> Response {
    let method = request.method().clone();
    let route = request.extensions().get::<MatchedPath>().map(|p| p.as_str().to_owned()).unwrap_or_default();
    let start = Instant::now();
    let response = next.run(request).await;
    let status = response.status().as_u16();
    let duration_ms = start.elapsed().as_millis() as u64;
    if route != "/healthz" {
        tracing::info!(methode = %method, route = %route, statut = status, duree_ms = duration_ms, "requête");
    }
    response
}
