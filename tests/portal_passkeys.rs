mod common;

use agendo_webauthn::soft::Authenticator;
use axum::http::{Method, StatusCode};
use chrono::Duration;
use common::{ORIGIN, RP_ID, TestApp, invite, onboard, passkey_login, register_invitation};
use serde_json::json;
use sqlx::PgPool;

#[sqlx::test]
async fn invitation_registers_passkey(pool: PgPool) {
    let app = TestApp::new(pool.clone());
    let token = invite(&app, "alice@exemple.fr").await;
    let page = app.get(&format!("/invitation/{token}")).await;
    assert_eq!(page.status, StatusCode::OK);
    assert!(page.text().contains("data-webauthn=\"register\""), "{}", page.text());
    assert!(page.text().contains("/static/webauthn.js"));

    let options = app.request(Method::POST, &format!("/invitation/{token}/options")).json(&json!({})).send().await.json();
    assert_eq!(options["rp"]["id"], RP_ID);
    assert_eq!(options["user"]["name"], "alice@exemple.fr");
    assert_eq!(options["authenticatorSelection"]["userVerification"], "required");
    assert_eq!(options["authenticatorSelection"]["residentKey"], "required");
    assert_eq!(options["attestation"], "none");
    assert_eq!(options["pubKeyCredParams"].as_array().unwrap().len(), 3);

    let authenticator = Authenticator::new(1);
    let r = register_invitation(&app, &token, &authenticator).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
    assert_eq!(r.json()["redirect"], "/maisons");
    let session = r.session_cookie().unwrap();
    assert_eq!(app.request(Method::GET, "/maisons").session(&session).send().await.status, StatusCode::OK);

    let (status, name): (String, String) =
        sqlx::query_as("SELECT a.status, p.name FROM accounts a JOIN passkeys p ON p.account_id = a.id").fetch_one(&pool).await.unwrap();
    assert_eq!((status.as_str(), name.as_str()), ("active", "iPhone"));
    let events: Vec<String> = sqlx::query_scalar("SELECT event FROM audit ORDER BY id").fetch_all(&pool).await.unwrap();
    assert_eq!(events, ["invitation_sent", "account_activated"]);
}

#[sqlx::test]
async fn invitation_expired_or_used(pool: PgPool) {
    let app = TestApp::new(pool);
    // Déjà utilisée.
    let token = invite(&app, "alice@exemple.fr").await;
    assert_eq!(register_invitation(&app, &token, &Authenticator::new(1)).await.status, StatusCode::OK);
    let page = app.get(&format!("/invitation/{token}")).await;
    assert_eq!(page.status, StatusCode::GONE);
    assert!(page.text().contains("déjà utilisée"), "{}", page.text());
    let options = app.request(Method::POST, &format!("/invitation/{token}/options")).json(&json!({})).send().await;
    assert_eq!(options.status, StatusCode::GONE);
    assert!(options.json()["error"].as_str().is_some());

    // Expirée.
    let token = invite(&app, "bob@exemple.fr").await;
    app.clock.advance(Duration::days(7));
    let page = app.get(&format!("/invitation/{token}")).await;
    assert_eq!(page.status, StatusCode::GONE);
    assert!(page.text().contains("expirée"), "{}", page.text());

    // Inconnue ou malformée.
    for token in ["inconnu", "%00%ff", &"a".repeat(500)] {
        assert_eq!(app.get(&format!("/invitation/{token}")).await.status, StatusCode::NOT_FOUND, "{token}");
    }
}

#[sqlx::test]
async fn passkey_login_opens_session(pool: PgPool) {
    let app = TestApp::new(pool.clone());
    let (_, mut authenticator) = onboard(&app, "alice@exemple.fr", 1).await;
    let r = common::passkey_login(&app, &mut authenticator).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
    assert_eq!(r.json()["redirect"], "/maisons");
    let session = r.session_cookie().unwrap();
    assert_eq!(app.request(Method::GET, "/maisons").session(&session).send().await.status, StatusCode::OK);
    let (count, used): (i64, Option<chrono::DateTime<chrono::Utc>>) =
        sqlx::query_as("SELECT sign_count, last_used_at FROM passkeys").fetch_one(&pool).await.unwrap();
    assert_eq!(count, 1);
    assert!(used.is_some());
}

#[sqlx::test]
async fn passkey_login_unknown_credential(pool: PgPool) {
    let app = TestApp::new(pool);
    onboard(&app, "alice@exemple.fr", 1).await;
    let r = passkey_login(&app, &mut Authenticator::new(9)).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    assert!(r.session_cookie().is_none());
}

#[sqlx::test]
async fn challenge_single_use(pool: PgPool) {
    let app = TestApp::new(pool);
    let (_, mut authenticator) = onboard(&app, "alice@exemple.fr", 1).await;
    let options = app.request(Method::POST, "/connexion/passkey/options").json(&json!({})).send().await.json();
    let challenge = options["challenge"].as_str().unwrap();
    let credential = authenticator.assert(RP_ID, ORIGIN, challenge);
    let finish = || app.request(Method::POST, "/connexion/passkey/terminer").json(&json!({"credential": credential}));
    assert_eq!(finish().send().await.status, StatusCode::OK);
    assert_eq!(finish().send().await.status, StatusCode::UNAUTHORIZED);
    // Défi expiré (5 min).
    let options = app.request(Method::POST, "/connexion/passkey/options").json(&json!({})).send().await.json();
    let credential = authenticator.assert(RP_ID, ORIGIN, options["challenge"].as_str().unwrap());
    app.clock.advance(Duration::minutes(5));
    let r = app.request(Method::POST, "/connexion/passkey/terminer").json(&json!({"credential": credential})).send().await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
}

#[sqlx::test]
async fn wrong_origin_refused(pool: PgPool) {
    let app = TestApp::new(pool.clone());
    let token = invite(&app, "alice@exemple.fr").await;
    let options = app.request(Method::POST, &format!("/invitation/{token}/options")).json(&json!({})).send().await.json();
    let credential = Authenticator::new(1).register(RP_ID, "https://evil.example", options["challenge"].as_str().unwrap());
    let r = app
        .request(Method::POST, &format!("/invitation/{token}/terminer"))
        .json(&json!({"credential": credential, "name": "x"}))
        .send()
        .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    let passkeys: i64 = sqlx::query_scalar("SELECT count(*) FROM passkeys").fetch_one(&pool).await.unwrap();
    assert_eq!(passkeys, 0);
    // L'invitation reste utilisable après un échec.
    assert_eq!(register_invitation(&app, &token, &Authenticator::new(1)).await.status, StatusCode::OK);
}

async fn add_passkey(app: &TestApp, session: &str, authenticator: &Authenticator) -> common::TestResponse {
    let options = app.request(Method::POST, "/compte/passkeys/options").session(session).json(&json!({})).send().await;
    assert_eq!(options.status, StatusCode::OK, "{}", options.text());
    let options = options.json();
    assert_eq!(options["excludeCredentials"].as_array().unwrap().len(), 1);
    let credential = authenticator.register(RP_ID, ORIGIN, options["challenge"].as_str().unwrap());
    app.request(Method::POST, "/compte/passkeys/terminer")
        .session(session)
        .json(&json!({"credential": credential, "name": "Mac"}))
        .send()
        .await
}

#[sqlx::test]
async fn add_and_remove_passkey(pool: PgPool) {
    let app = TestApp::new(pool.clone());
    let (session, _) = onboard(&app, "alice@exemple.fr", 1).await;
    let r = add_passkey(&app, &session, &Authenticator::new(2)).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
    assert_eq!(r.json()["redirect"], "/compte");
    let ids: Vec<uuid::Uuid> = sqlx::query_scalar("SELECT id FROM passkeys ORDER BY created_at, name").fetch_all(&pool).await.unwrap();
    assert_eq!(ids.len(), 2);
    let r = app.request(Method::POST, &format!("/compte/passkeys/{}/retirer", ids[0])).session(&session).form(&[]).send().await;
    assert_eq!(r.status, StatusCode::SEE_OTHER);
    let left: i64 = sqlx::query_scalar("SELECT count(*) FROM passkeys").fetch_one(&pool).await.unwrap();
    assert_eq!(left, 1);
    // Sans session : rien.
    let r = app.request(Method::POST, "/compte/passkeys/options").json(&json!({})).send().await;
    assert_eq!(r.status, StatusCode::SEE_OTHER);
}

#[sqlx::test]
async fn cannot_remove_last_passkey(pool: PgPool) {
    let app = TestApp::new(pool.clone());
    let (session, _) = onboard(&app, "alice@exemple.fr", 1).await;
    let (bob_session, _) = onboard(&app, "bob@exemple.fr", 2).await;
    let alice_key: uuid::Uuid = sqlx::query_scalar(
        "SELECT p.id FROM passkeys p JOIN accounts a ON a.id = p.account_id WHERE a.email = 'alice@exemple.fr'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    let r = app.request(Method::POST, &format!("/compte/passkeys/{alice_key}/retirer")).session(&session).form(&[]).send().await;
    assert_eq!(r.status, StatusCode::CONFLICT);
    // La passkey d'une autre personne ne se retire pas.
    add_passkey(&app, &bob_session, &Authenticator::new(3)).await;
    let r = app.request(Method::POST, &format!("/compte/passkeys/{alice_key}/retirer")).session(&bob_session).form(&[]).send().await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
    let left: i64 = sqlx::query_scalar("SELECT count(*) FROM passkeys").fetch_one(&pool).await.unwrap();
    assert_eq!(left, 3);
}
