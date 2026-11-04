//! Binaire `agendo-access-cloud` : serveur, migrations, clé de signature et administration.

use std::{net::SocketAddr, path::PathBuf, process::ExitCode};

use agendo_access_cloud::{AppState, MIGRATOR, admin, app, config, signing};
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
    /// Sert l'API des maisons et le portail (migrations appliquées au démarrage).
    Serve,
    /// Applique les migrations de la base.
    Migrate,
    /// Crée une graine de clé de signature dans un fichier (jamais écrasé).
    Keygen {
        /// Identifiant de la clé (`kid`), par exemple `k1`.
        #[arg(long)]
        kid: String,
        /// Fichier à créer (mode 0600).
        file: PathBuf,
    },
    /// Administration des comptes et des maisons.
    Admin {
        #[command(subcommand)]
        command: AdminCommand,
    },
}

#[derive(Subcommand)]
enum AdminCommand {
    /// Invite une personne (ou renvoie une invitation à un compte encore invité).
    Invite { email: String },
    /// Liste les comptes.
    List,
    /// Suspend l'abonnement d'un compte.
    Suspend { email: String },
    /// Rétablit l'abonnement d'un compte.
    Resume { email: String },
    /// Révoque une maison, par nom d'hôte ou par étiquette.
    RevokeHouse { host: String },
}

/// Logs JSON sur la sortie d'erreur, en français, filtrés par `RUST_LOG` (`info,sqlx=warn` par défaut).
fn init_logs() {
    use tracing_subscriber::EnvFilter;
    tracing_subscriber::fmt()
        .json()
        .with_writer(std::io::stderr)
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info,sqlx=warn")))
        .with_current_span(false)
        .init();
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(_) => std::future::pending().await,
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        () = ctrl_c => {}
        () = terminate => {}
    }
    tracing::info!("arrêt demandé : fin des requêtes en cours");
}

async fn serve() -> anyhow::Result<()> {
    let state = AppState::from_env().await?;
    MIGRATOR.run(&state.db).await?;
    let listen = state.config.listen;
    let listener = tokio::net::TcpListener::bind(listen).await?;
    tracing::info!(adresse = %listen, kid = state.signer.kid(), zone = %state.config.zone, "plan de contrôle à l'écoute");
    axum::serve(listener, app(state).into_make_service_with_connect_info::<SocketAddr>())
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

async fn run(command: Command) -> anyhow::Result<()> {
    match command {
        Command::Serve => serve().await?,
        Command::Migrate => {
            let url = config::database_url(&config::Env)?;
            let pool = PgPoolOptions::new().max_connections(2).connect(&url).await?;
            MIGRATOR.run(&pool).await?;
            println!("Migrations appliquées.");
        }
        Command::Keygen { kid, file } => print!("{}", signing::keygen(&file, &kid)?),
        Command::Admin { command } => {
            let state = AppState::from_env().await?;
            let output = match command {
                AdminCommand::Invite { email } => admin::invite(&state, &email).await?,
                AdminCommand::List => admin::list(&state).await?,
                AdminCommand::Suspend { email } => admin::suspend(&state, &email).await?,
                AdminCommand::Resume { email } => admin::resume(&state, &email).await?,
                AdminCommand::RevokeHouse { host } => admin::revoke_house(&state, &host).await?,
            };
            println!("{}", output.trim_end());
        }
    }
    Ok(())
}

#[tokio::main]
async fn main() -> ExitCode {
    init_logs();
    match run(Cli::parse().command).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("erreur : {e:#}");
            ExitCode::FAILURE
        }
    }
}
