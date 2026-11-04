//! État partagé des requêtes.

use std::{sync::Arc, time::Duration};

use anyhow::Context;
use sqlx::{PgPool, postgres::PgPoolOptions};

use crate::{
    clock::{Clock, SystemClock},
    config::{self, Config, Env},
    dns::{self, DnsProvider},
    mail::{self, Mailer},
    signing::Signer,
};

#[derive(Clone)]
pub struct AppState {
    pub db: PgPool,
    pub config: Arc<Config>,
    pub clock: Arc<dyn Clock>,
    pub mailer: Arc<dyn Mailer>,
    pub dns: Arc<dyn DnsProvider>,
    pub signer: Arc<Signer>,
}

impl AppState {
    /// État de production, entièrement lu de l'environnement (variables et fichiers montés).
    pub async fn from_env() -> anyhow::Result<Self> {
        let config = Config::from_env()?;
        let db = PgPoolOptions::new()
            .max_connections(10)
            .acquire_timeout(Duration::from_secs(5))
            .connect(&config::database_url(&Env)?)
            .await
            .context("connexion à PostgreSQL impossible")?;
        Ok(Self {
            db,
            config: Arc::new(config),
            clock: Arc::new(SystemClock),
            mailer: mail::from_env(&Env)?,
            dns: dns::from_env(&Env)?,
            signer: Arc::new(Signer::from_env(&Env)?),
        })
    }
}
