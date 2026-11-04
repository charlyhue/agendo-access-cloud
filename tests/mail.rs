use std::sync::{Arc, Mutex};

use agendo_access_cloud::mail::{Mail, Mailer, OutboxMailer, ResendMailer};
use axum::{Json, Router, extract::State, http::HeaderMap, http::StatusCode, routing::post};

type Seen = Arc<Mutex<Vec<(Option<String>, serde_json::Value)>>>;

/// Faux Resend local : garde les requêtes reçues, répond `status`.
async fn fake_resend(status: StatusCode) -> (String, Seen) {
    let seen: Seen = Arc::default();
    let app = Router::new()
        .route(
            "/emails",
            post(|State((seen, status)): State<(Seen, StatusCode)>, headers: HeaderMap, Json(body): Json<serde_json::Value>| async move {
                let auth = headers.get("authorization").and_then(|v| v.to_str().ok()).map(str::to_owned);
                seen.lock().unwrap().push((auth, body));
                (status, Json(serde_json::json!({"id": "x", "message": "adresse secrete@exemple.fr refusée"})))
            }),
        )
        .with_state((seen.clone(), status));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (url, seen)
}

fn mail() -> Mail {
    Mail { to: "alice@exemple.fr".into(), subject: "Sujet".into(), text: "texte".into(), html: "<p>texte</p>".into() }
}

#[tokio::test]
async fn resend_posts_email() {
    let (url, seen) = fake_resend(StatusCode::OK).await;
    let mailer = ResendMailer::new(&url, "cle-de-test".into(), "Agendo Access <ne-pas-repondre@exemple.fr>".into());
    mailer.send(mail()).await.unwrap();
    let (auth, body) = seen.lock().unwrap().pop().unwrap();
    assert_eq!(auth.as_deref(), Some("Bearer cle-de-test"));
    assert_eq!(
        body,
        serde_json::json!({"from": "Agendo Access <ne-pas-repondre@exemple.fr>", "to": ["alice@exemple.fr"],
            "subject": "Sujet", "text": "texte", "html": "<p>texte</p>"})
    );
}

#[tokio::test]
async fn resend_error_hides_body() {
    let (url, _) = fake_resend(StatusCode::UNPROCESSABLE_ENTITY).await;
    let mailer = ResendMailer::new(&url, "cle-de-test".into(), "x@exemple.fr".into());
    let err = mailer.send(mail()).await.unwrap_err().to_string();
    assert!(err.contains("422"), "{err}");
    assert!(!err.contains("secrete") && !err.contains("cle-de-test"), "{err}");
}

#[tokio::test]
async fn outbox_writes_files() {
    let dir = tempfile::tempdir().unwrap();
    OutboxMailer::new(dir.path().into()).send(mail()).await.unwrap();
    let files: Vec<_> = std::fs::read_dir(dir.path()).unwrap().collect();
    assert_eq!(files.len(), 1);
    let content = std::fs::read_to_string(files[0].as_ref().unwrap().path()).unwrap();
    assert!(content.contains("alice@exemple.fr") && content.contains("Sujet") && content.contains("texte"));
}
