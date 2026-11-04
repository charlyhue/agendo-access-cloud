mod common;

use agendo_access_cloud::admin;
use agendo_access_protocol::api::{EnrollResponse, host_in_zone};
use axum::http::{Method, StatusCode};
use chrono::Duration;
use common::{TestApp, enroll, enrollment_code, onboard};
use sqlx::PgPool;

fn reason(r: &common::TestResponse) -> String {
    r.json()["reason"].as_str().unwrap_or_default().to_owned()
}

#[sqlx::test]
async fn enroll_flow(pool: PgPool) {
    let app = TestApp::new(pool.clone());
    let (session, _) = onboard(&app, "alice@exemple.fr", 1).await;
    let code = enrollment_code(&app, &session).await;
    assert_eq!(code.len(), 9, "{code}");
    let r = enroll(&app, &code, 2, "Maison de vacances").await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
    let response: EnrollResponse = serde_json::from_slice(&r.body).unwrap();
    assert!(host_in_zone(&response.host, "maisons.exemple.fr"), "{}", response.host);
    assert!(uuid::Uuid::parse_str(&response.house_id).is_ok());
    assert_eq!(response.relays, app.state.config.relays);
    assert_eq!(response.push_urls, app.state.config.push_urls);
    assert_eq!(response.trusted_keys, app.state.signer.trusted());

    let page = app.request(Method::GET, "/maisons").session(&session).send().await.text();
    assert!(page.contains(&response.host) && page.contains("Maison de vacances"), "{page}");
    let events: Vec<String> = sqlx::query_scalar("SELECT event FROM audit WHERE house_id IS NOT NULL").fetch_all(&pool).await.unwrap();
    assert_eq!(events, ["house_enrolled"]);
    // Le code n'est rangé que haché.
    let clear: i64 = sqlx::query_scalar("SELECT count(*) FROM enrollment_codes WHERE code_hash = $1")
        .bind(code.replace('-', "").as_bytes())
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(clear, 0);
}

#[sqlx::test]
async fn enroll_accepts_loose_code(pool: PgPool) {
    let app = TestApp::new(pool);
    let (session, _) = onboard(&app, "alice@exemple.fr", 1).await;
    let code = enrollment_code(&app, &session).await;
    let loose = format!(" {} ", code.to_lowercase().replace('-', " - "));
    let r = enroll(&app, &loose, 2, "Maison").await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
}

#[sqlx::test]
async fn enroll_code_single_use(pool: PgPool) {
    let app = TestApp::new(pool.clone());
    let (session, _) = onboard(&app, "alice@exemple.fr", 1).await;
    let code = enrollment_code(&app, &session).await;
    assert_eq!(enroll(&app, &code, 2, "Maison").await.status, StatusCode::OK);
    let again = enroll(&app, &code, 3, "Autre").await;
    assert_eq!(again.status, StatusCode::BAD_REQUEST);
    assert_eq!(reason(&again), "invalid_code");
    let houses: i64 = sqlx::query_scalar("SELECT count(*) FROM houses").fetch_one(&pool).await.unwrap();
    assert_eq!(houses, 1);
}

#[sqlx::test]
async fn enroll_code_expired(pool: PgPool) {
    let app = TestApp::new(pool);
    let (session, _) = onboard(&app, "alice@exemple.fr", 1).await;
    let code = enrollment_code(&app, &session).await;
    app.clock.advance(Duration::minutes(15));
    let r = enroll(&app, &code, 2, "Maison").await;
    assert_eq!((r.status, reason(&r).as_str()), (StatusCode::BAD_REQUEST, "invalid_code"));
    let r = enroll(&app, "pas-un-code", 2, "Maison").await;
    assert_eq!(reason(&r), "invalid_code");
}

#[sqlx::test]
async fn enroll_bad_key_or_name(pool: PgPool) {
    let app = TestApp::new(pool);
    let (session, _) = onboard(&app, "alice@exemple.fr", 1).await;
    let code = enrollment_code(&app, &session).await;
    let bad_key = app
        .request(Method::POST, "/v1/houses/enroll")
        .json(&serde_json::json!({"code": code, "house_key": "pas-une-cle", "name": "Maison"}))
        .send()
        .await;
    assert_eq!((bad_key.status, reason(&bad_key).as_str()), (StatusCode::BAD_REQUEST, "bad_request"));
    for name in ["", "   ", &"x".repeat(65), "Maison\u{0007}"] {
        let r = enroll(&app, &code, 2, name).await;
        assert_eq!((r.status, reason(&r).as_str()), (StatusCode::BAD_REQUEST, "bad_request"), "{name:?}");
    }
    let not_json = app.request(Method::POST, "/v1/houses/enroll").bytes(b"{".to_vec()).send().await;
    assert_eq!(reason(&not_json), "bad_request");
    // Le code n'a pas été consommé par ces échecs ; un nom de 64 octets passe.
    assert_eq!(enroll(&app, &code, 2, &"é".repeat(32)).await.status, StatusCode::OK);
    // Même clé de maison une seconde fois : refus.
    let code = enrollment_code(&app, &session).await;
    let r = enroll(&app, &code, 2, "Maison").await;
    assert_eq!((r.status, reason(&r).as_str()), (StatusCode::BAD_REQUEST, "bad_request"));
}

#[sqlx::test]
async fn enroll_rate_limited(pool: PgPool) {
    let app = TestApp::new(pool);
    let mut last = StatusCode::OK;
    for _ in 0..31 {
        last = enroll(&app, "ABCD2345", 2, "Maison").await.status;
    }
    assert_eq!(last, StatusCode::TOO_MANY_REQUESTS);
}

#[sqlx::test]
async fn enroll_subscription_inactive(pool: PgPool) {
    let app = TestApp::new(pool);
    let (session, _) = onboard(&app, "alice@exemple.fr", 1).await;
    let code = enrollment_code(&app, &session).await;
    admin::suspend(&app.state, "alice@exemple.fr").await.unwrap();
    let r = enroll(&app, &code, 2, "Maison").await;
    assert_eq!((r.status, reason(&r).as_str()), (StatusCode::FORBIDDEN, "subscription_inactive"));
    let page = app.request(Method::POST, "/maisons/rattacher").session(&session).form(&[]).send().await;
    assert_eq!(page.status, StatusCode::FORBIDDEN);
    let list = app.request(Method::GET, "/maisons").session(&session).send().await.text();
    assert!(list.contains("Abonnement inactif") && !list.contains("/maisons/rattacher"), "{list}");
}

#[sqlx::test]
async fn portal_revoke_house(pool: PgPool) {
    let app = TestApp::new(pool.clone());
    let (session, _) = onboard(&app, "alice@exemple.fr", 1).await;
    let code = enrollment_code(&app, &session).await;
    let house: EnrollResponse = serde_json::from_slice(&enroll(&app, &code, 2, "Maison").await.body).unwrap();
    let r = app.request(Method::POST, &format!("/maisons/{}/revoquer", house.house_id)).session(&session).form(&[]).send().await;
    assert_eq!(r.status, StatusCode::SEE_OTHER);
    let revoked: bool = sqlx::query_scalar("SELECT revoked_at IS NOT NULL FROM houses").fetch_one(&pool).await.unwrap();
    assert!(revoked);
    let page = app.request(Method::GET, "/maisons").session(&session).send().await.text();
    assert!(page.contains("Révoquée"), "{page}");
    let again = app.request(Method::POST, &format!("/maisons/{}/revoquer", house.house_id)).session(&session).form(&[]).send().await;
    assert_eq!(again.status, StatusCode::NOT_FOUND);
}

#[sqlx::test]
async fn admin_revoke_house(pool: PgPool) {
    let app = TestApp::new(pool.clone());
    let (session, _) = onboard(&app, "alice@exemple.fr", 1).await;
    let first: EnrollResponse =
        serde_json::from_slice(&enroll(&app, &enrollment_code(&app, &session).await, 2, "A").await.body).unwrap();
    let second: EnrollResponse =
        serde_json::from_slice(&enroll(&app, &enrollment_code(&app, &session).await, 3, "B").await.body).unwrap();
    let out = admin::revoke_house(&app.state, &first.host.to_uppercase()).await.unwrap();
    assert!(out.contains(&first.host), "{out}");
    let label = second.host.split('.').next().unwrap();
    admin::revoke_house(&app.state, label).await.unwrap();
    let revoked: i64 = sqlx::query_scalar("SELECT count(*) FROM houses WHERE revoked_at IS NOT NULL").fetch_one(&pool).await.unwrap();
    assert_eq!(revoked, 2);
    assert!(admin::revoke_house(&app.state, "aaaaaaaaaaaaaaaa").await.is_err());
    assert!(admin::revoke_house(&app.state, label).await.unwrap().contains("déjà"));
    let list = admin::list(&app.state).await.unwrap();
    assert!(list.lines().any(|l| l.contains("alice@exemple.fr") && l.contains(" 0 ")), "{list}");
}

#[sqlx::test]
async fn houses_of_other_account_hidden(pool: PgPool) {
    let app = TestApp::new(pool.clone());
    let (alice, _) = onboard(&app, "alice@exemple.fr", 1).await;
    let (bob, _) = onboard(&app, "bob@exemple.fr", 2).await;
    let house: EnrollResponse =
        serde_json::from_slice(&enroll(&app, &enrollment_code(&app, &alice).await, 2, "Chez Alice").await.body).unwrap();
    let page = app.request(Method::GET, "/maisons").session(&bob).send().await.text();
    assert!(!page.contains(&house.host) && !page.contains("Chez Alice"));
    let r = app.request(Method::POST, &format!("/maisons/{}/revoquer", house.house_id)).session(&bob).form(&[]).send().await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
    let revoked: bool = sqlx::query_scalar("SELECT revoked_at IS NOT NULL FROM houses").fetch_one(&pool).await.unwrap();
    assert!(!revoked);
}
