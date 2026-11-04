mod common;

use axum::http::StatusCode;
use common::TestApp;
use sqlx::PgPool;

#[sqlx::test]
async fn health_ok(pool: PgPool) {
    let app = TestApp::new(pool);
    let response = app.get("/healthz").await;
    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(response.text(), "ok");
}
