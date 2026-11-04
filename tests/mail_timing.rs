//! La réponse à une demande de code ne doit pas dépendre de l'envoi du courrier : sinon son
//! délai révèle quelles adresses ont un compte.
mod common;

use std::{sync::Arc, time::{Duration, Instant}};

use agendo_access_cloud::{
    app,
    mail::{Mail, Mailer, MemoryMailer},
};
use async_trait::async_trait;
use axum::{body::Body, http::Request};
use common::{TestApp, active_account};
use sqlx::PgPool;
use tower::ServiceExt;

struct SlowMailer(Arc<MemoryMailer>);

#[async_trait]
impl Mailer for SlowMailer {
    async fn send(&self, mail: Mail) -> anyhow::Result<()> {
        tokio::time::sleep(Duration::from_millis(1500)).await;
        self.0.send(mail).await
    }
}

#[sqlx::test]
async fn code_response_does_not_wait_for_mail(pool: PgPool) {
    let test = TestApp::new(pool);
    active_account(&test, "alice@exemple.fr").await;
    let sent = Arc::new(MemoryMailer::default());
    let mut state = test.state.clone();
    state.mailer = Arc::new(SlowMailer(sent.clone()));
    let request = Request::post("/connexion/code")
        .header("origin", state.config.portal_origin())
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from("email=alice%40exemple.fr"))
        .unwrap();
    let start = Instant::now();
    let response = app(state).oneshot(request).await.unwrap();
    assert_eq!(response.status(), 200);
    assert!(start.elapsed() < Duration::from_millis(500), "réponse en {:?}", start.elapsed());
    // Le courrier part quand même.
    tokio::time::sleep(Duration::from_millis(2000)).await;
    assert_eq!(sent.sent().len(), 1);
}
