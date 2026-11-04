mod common;

use axum::http::{Method, StatusCode};
use common::{TestApp, account_id, insert_house, login, onboard};
use sqlx::PgPool;

#[sqlx::test]
async fn account_page_lists_passkeys_and_sessions(pool: PgPool) {
    let app = TestApp::new(pool);
    let (session, _) = onboard(&app, "alice@exemple.fr", 1).await;
    let page = app.request(Method::GET, "/compte").session(&session).send().await;
    assert_eq!(page.status, StatusCode::OK);
    let text = page.text();
    for expected in ["alice@exemple.fr", "iPhone", "Cette session", "data-webauthn=\"register\"", "/compte/export", "/compte/supprimer"] {
        assert!(text.contains(expected), "{expected} absent : {text}");
    }
}

#[sqlx::test]
async fn revoke_other_session(pool: PgPool) {
    let app = TestApp::new(pool.clone());
    let (first, _) = onboard(&app, "alice@exemple.fr", 1).await;
    let second = login(&app, "alice@exemple.fr").await;
    let other: uuid::Uuid = sqlx::query_scalar("SELECT id FROM sessions WHERE token_hash = sha256($1::text::bytea)")
        .bind(&second)
        .fetch_one(&pool)
        .await
        .unwrap();
    let r = app.request(Method::POST, &format!("/compte/sessions/{other}/revoquer")).session(&first).form(&[]).send().await;
    assert_eq!(r.status, StatusCode::SEE_OTHER);
    assert_eq!(app.request(Method::GET, "/maisons").session(&second).send().await.status, StatusCode::SEE_OTHER);
    assert_eq!(app.request(Method::GET, "/maisons").session(&first).send().await.status, StatusCode::OK);
    // Une session d'un autre compte ne se révoque pas.
    let (bob, _) = onboard(&app, "bob@exemple.fr", 2).await;
    let first_id: uuid::Uuid = sqlx::query_scalar("SELECT id FROM sessions WHERE token_hash = sha256($1::text::bytea)")
        .bind(&first)
        .fetch_one(&pool)
        .await
        .unwrap();
    let r = app.request(Method::POST, &format!("/compte/sessions/{first_id}/revoquer")).session(&bob).form(&[]).send().await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
}

#[sqlx::test]
async fn export_contains_no_secret(pool: PgPool) {
    let app = TestApp::new(pool.clone());
    let (session, _) = onboard(&app, "alice@exemple.fr", 1).await;
    let account = account_id(&app, "alice@exemple.fr").await;
    insert_house(&app, account, "abcdefghijklmnop", 2).await;
    let r = app.request(Method::GET, "/compte/export").session(&session).send().await;
    assert_eq!(r.status, StatusCode::OK);
    assert!(r.headers.get("content-disposition").unwrap().to_str().unwrap().starts_with("attachment"));
    let data = r.json();
    assert_eq!(data["compte"]["email"], "alice@exemple.fr");
    assert_eq!(data["compte"]["abonnement"]["actif"], true);
    assert_eq!(data["passkeys"][0]["nom"], "iPhone");
    assert_eq!(data["maisons"][0]["nom_hote"], "abcdefghijklmnop.maisons.exemple.fr");
    assert!(!data["sessions"].as_array().unwrap().is_empty());
    assert!(!data["journal"].as_array().unwrap().is_empty());
    let text = r.text();
    let (public_key, house_key): (Vec<u8>, String) =
        sqlx::query_as("SELECT p.public_key, h.public_key FROM passkeys p, houses h").fetch_one(&pool).await.unwrap();
    assert!(!text.contains(&agendo_webauthn::b64(&public_key)));
    assert!(!text.contains(&house_key));
    assert!(!text.contains(&session));
    for field in ["hash", "public_key", "webauthn_user_id", "credential"] {
        assert!(!text.contains(field), "{field} dans l'export");
    }
}

#[sqlx::test]
async fn delete_account_detaches_houses(pool: PgPool) {
    let app = TestApp::new(pool.clone());
    let (session, _) = onboard(&app, "alice@exemple.fr", 1).await;
    let account = account_id(&app, "alice@exemple.fr").await;
    let house = insert_house(&app, account, "abcdefghijklmnop", 2).await;
    let r = app
        .request(Method::POST, "/compte/supprimer")
        .session(&session)
        .form(&[("confirmation", " Alice@exemple.fr ")])
        .send()
        .await;
    assert_eq!(r.status, StatusCode::SEE_OTHER, "{}", r.text());
    assert_eq!(r.session_cookie().as_deref(), Some(""));
    let accounts: i64 = sqlx::query_scalar("SELECT count(*) FROM accounts").fetch_one(&pool).await.unwrap();
    assert_eq!(accounts, 0);
    let (owner, name, revoked): (Option<uuid::Uuid>, String, Option<chrono::DateTime<chrono::Utc>>) =
        sqlx::query_as("SELECT account_id, name, revoked_at FROM houses WHERE id = $1").bind(house).fetch_one(&pool).await.unwrap();
    assert_eq!((owner, name.as_str()), (None, ""));
    assert!(revoked.is_some());
    let leftovers: i64 = sqlx::query_scalar(
        "SELECT (SELECT count(*) FROM passkeys) + (SELECT count(*) FROM sessions) + (SELECT count(*) FROM invitations)
              + (SELECT count(*) FROM audit WHERE account_id IS NOT NULL)",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(leftovers, 0);
    let deleted: i64 = sqlx::query_scalar("SELECT count(*) FROM audit WHERE event = 'account_deleted'").fetch_one(&pool).await.unwrap();
    assert_eq!(deleted, 1);
    assert_eq!(app.request(Method::GET, "/maisons").session(&session).send().await.status, StatusCode::SEE_OTHER);
}

#[sqlx::test]
async fn delete_requires_confirmation(pool: PgPool) {
    let app = TestApp::new(pool.clone());
    let (session, _) = onboard(&app, "alice@exemple.fr", 1).await;
    let r = app.request(Method::POST, "/compte/supprimer").session(&session).form(&[("confirmation", "oui")]).send().await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    let accounts: i64 = sqlx::query_scalar("SELECT count(*) FROM accounts").fetch_one(&pool).await.unwrap();
    assert_eq!(accounts, 1);
}
