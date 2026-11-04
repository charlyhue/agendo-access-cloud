mod common;

use std::sync::{Arc, Mutex};

use axum::http::Method;
use common::{TestApp, invite};
use sqlx::PgPool;

#[derive(Clone, Default)]
struct Buffer(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for Buffer {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Le journal des requêtes nomme la route, jamais l'URI : le lien d'invitation est un secret.
#[sqlx::test]
async fn request_log_hides_tokens(pool: PgPool) {
    let buffer = Buffer::default();
    let writer = buffer.clone();
    let subscriber = tracing_subscriber::fmt().json().with_writer(move || writer.clone()).finish();
    let _guard = tracing::subscriber::set_default(subscriber);

    let app = TestApp::new(pool);
    let token = invite(&app, "alice@exemple.fr").await;
    app.get(&format!("/invitation/{token}")).await;
    app.request(Method::POST, &format!("/invitation/{token}/options")).json(&serde_json::json!({})).send().await;

    let logs = String::from_utf8(buffer.0.lock().unwrap().clone()).unwrap();
    assert!(logs.contains("/invitation/{token}"), "{logs}");
    assert!(!logs.contains(&token), "jeton d'invitation dans les logs : {logs}");
    assert!(!logs.contains("alice@exemple.fr"), "adresse dans les logs : {logs}");
}
