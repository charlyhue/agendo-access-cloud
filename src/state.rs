//! État partagé des requêtes.

use std::sync::Arc;

use sqlx::PgPool;

use crate::{clock::Clock, config::Config, dns::DnsProvider, mail::Mailer, signing::Signer};

#[derive(Clone)]
pub struct AppState {
    pub db: PgPool,
    pub config: Arc<Config>,
    pub clock: Arc<dyn Clock>,
    pub mailer: Arc<dyn Mailer>,
    pub dns: Arc<dyn DnsProvider>,
    pub signer: Arc<Signer>,
}
