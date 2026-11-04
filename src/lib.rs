//! Plan de contrôle et portail d'Agendo Access.
//!
//! Un seul serveur axum : l'API des maisons (`/v1/*`, `/.well-known/agendo-access/*`) et le
//! portail (tout le reste). Sans état hors de PostgreSQL : deux instances peuvent tourner.

pub mod admin;
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

use axum::{Router, extract::State, http::StatusCode, routing::get};

pub use state::AppState;

/// Migrations du schéma (`migrations/`), appliquées au démarrage de `serve` et par `migrate`.
pub static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!();

pub fn app(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(health))
        .merge(portal::routes(state.clone()))
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
