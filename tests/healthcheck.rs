mod common;

use agendo_access_cloud::{app, probe};
use common::TestApp;
use sqlx::PgPool;

#[sqlx::test]
async fn probe_reports_health(pool: PgPool) {
    let state = TestApp::new(pool).state;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app(state)).await.unwrap() });
    probe(addr).await.unwrap();
    // Écoute sur toutes les interfaces : la sonde vise la boucle locale.
    probe(std::net::SocketAddr::from(([0, 0, 0, 0], addr.port()))).await.unwrap();
    // Personne n'écoute ici.
    let free = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap();
    assert!(probe(free).await.is_err());
}
