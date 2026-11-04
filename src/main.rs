//! Binaire `agendo-access-cloud` : serveur, migrations et administration.

use agendo_access_cloud::{MIGRATOR, config};
use clap::{Parser, Subcommand};
use sqlx::postgres::PgPoolOptions;

#[derive(Parser)]
#[command(name = "agendo-access-cloud", about = "Plan de contrôle et portail d'Agendo Access")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Applique les migrations de la base.
    Migrate,
}

/// Logs JSON, en français, filtrés par `RUST_LOG` (`info` par défaut).
fn init_logs() {
    use tracing_subscriber::EnvFilter;
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with_current_span(false)
        .init();
}

async fn pool() -> anyhow::Result<sqlx::PgPool> {
    let url = config::database_url(&config::Env)?;
    Ok(PgPoolOptions::new().max_connections(10).connect(&url).await?)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_logs();
    match Cli::parse().command {
        Command::Migrate => {
            MIGRATOR.run(&pool().await?).await?;
            tracing::info!("migrations appliquées");
        }
    }
    Ok(())
}
