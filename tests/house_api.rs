mod common;

use agendo_access_cloud::{admin, clock::Clock};
use agendo_access_protocol::{
    SigningKey,
    api::{ACME_PATH, KeysResponse, TOKENS_PATH, TokensResponse},
    keys::TrustedKeys,
    token::{PushClaims, TunnelClaims},
};
use axum::http::{Method, StatusCode};
use common::{TestApp, enrolled_house, signed};
use sqlx::PgPool;

fn reason(r: &common::TestResponse) -> String {
    r.json()["reason"].as_str().unwrap_or_default().to_owned()
}

async fn tokens(app: &TestApp, house: &str, key: &SigningKey) -> common::TestResponse {
    signed(app, Method::POST, TOKENS_PATH, b"", house, key, app.clock.unix()).await
}

#[sqlx::test]
async fn tokens_flow(pool: PgPool) {
    let app = TestApp::new(pool.clone());
    let (house, key, session) = enrolled_house(&app, "alice@exemple.fr", 2).await;
    let r = tokens(&app, &house.house_id, &key).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
    let tokens: TokensResponse = serde_json::from_slice(&r.body).unwrap();
    let keys: KeysResponse = serde_json::from_slice(&app.get("/.well-known/agendo-access/keys").await.body).unwrap();
    let trusted = TrustedKeys::new(keys.keys).unwrap();
    let now = app.clock.unix();
    let tunnel = TunnelClaims::verify(&tokens.tunnel_token, &trusted, now).unwrap();
    assert_eq!((tunnel.sub.as_str(), tunnel.host.as_str()), (house.house_id.as_str(), house.host.as_str()));
    assert_eq!(tunnel.house_key().unwrap(), key.verifying_key());
    PushClaims::verify(&tokens.push_token, &trusted, now).unwrap();
    let last: Option<chrono::DateTime<chrono::Utc>> = sqlx::query_scalar("SELECT last_token_at FROM houses").fetch_one(&pool).await.unwrap();
    assert_eq!(last, Some(common::start()));
    let page = app.request(Method::GET, "/maisons").session(&session).send().await.text();
    assert!(page.contains("04/11/2026 12:00 UTC</td>\n        <td>04/11/2026 12:00 UTC"), "{page}");
}

#[sqlx::test]
async fn tokens_refuse_stale_signature(pool: PgPool) {
    let app = TestApp::new(pool);
    let (house, key, _) = enrolled_house(&app, "alice@exemple.fr", 2).await;
    for t in [app.clock.unix() - 61, app.clock.unix() + 61] {
        let r = signed(&app, Method::POST, TOKENS_PATH, b"", &house.house_id, &key, t).await;
        assert_eq!((r.status, reason(&r).as_str()), (StatusCode::UNAUTHORIZED, "bad_signature"));
        assert!(r.json()["detail"].as_str().unwrap().contains("horloge"), "{}", r.text());
    }
    let r = signed(&app, Method::POST, TOKENS_PATH, b"", &house.house_id, &key, app.clock.unix() - 60).await;
    assert_eq!(r.status, StatusCode::OK);
}

#[sqlx::test]
async fn signature_covers_query(pool: PgPool) {
    let app = TestApp::new(pool);
    let (house, key, _) = enrolled_house(&app, "alice@exemple.fr", 2).await;
    let signature = agendo_access_protocol::signature::sign_request(&key, "POST", TOKENS_PATH, b"", app.clock.unix());
    let r = app
        .request(Method::POST, &format!("{TOKENS_PATH}?x=1"))
        .header("agendo-house", &house.house_id)
        .header("agendo-signature", &signature)
        .send()
        .await;
    assert_eq!((r.status, reason(&r).as_str()), (StatusCode::UNAUTHORIZED, "bad_signature"));
    let r = signed(&app, Method::POST, &format!("{TOKENS_PATH}?x=1"), b"", &house.house_id, &key, app.clock.unix()).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
}

#[sqlx::test]
async fn tokens_unknown_house(pool: PgPool) {
    let app = TestApp::new(pool);
    let (house, key, _) = enrolled_house(&app, "alice@exemple.fr", 2).await;
    let other = SigningKey::from_bytes(&[7; 32]);
    let cases = [
        tokens(&app, &uuid::Uuid::new_v4().to_string(), &key).await,
        tokens(&app, "pas-un-uuid", &key).await,
        tokens(&app, &house.house_id, &other).await,
        app.request(Method::POST, TOKENS_PATH).send().await,
        app.request(Method::POST, TOKENS_PATH).header("agendo-house", &house.house_id).send().await,
    ];
    for r in cases {
        assert_eq!((r.status, reason(&r).as_str()), (StatusCode::UNAUTHORIZED, "bad_signature"), "{}", r.text());
    }
}

#[sqlx::test]
async fn tokens_revoked(pool: PgPool) {
    let app = TestApp::new(pool);
    let (house, key, _) = enrolled_house(&app, "alice@exemple.fr", 2).await;
    admin::revoke_house(&app.state, &house.host).await.unwrap();
    let r = tokens(&app, &house.house_id, &key).await;
    assert_eq!((r.status, reason(&r).as_str()), (StatusCode::FORBIDDEN, "revoked"));
}

#[sqlx::test]
async fn tokens_subscription_inactive(pool: PgPool) {
    let app = TestApp::new(pool);
    let (house, key, _) = enrolled_house(&app, "alice@exemple.fr", 2).await;
    admin::suspend(&app.state, "alice@exemple.fr").await.unwrap();
    let r = tokens(&app, &house.house_id, &key).await;
    assert_eq!((r.status, reason(&r).as_str()), (StatusCode::FORBIDDEN, "subscription_inactive"));
    admin::resume(&app.state, "alice@exemple.fr").await.unwrap();
    assert_eq!(tokens(&app, &house.house_id, &key).await.status, StatusCode::OK);
}

#[sqlx::test]
async fn tokens_rate_limited(pool: PgPool) {
    let app = TestApp::new(pool);
    let (house, key, _) = enrolled_house(&app, "alice@exemple.fr", 2).await;
    // Configuration de test : 20 requêtes signées par minute et par maison.
    for _ in 0..20 {
        assert_eq!(tokens(&app, &house.house_id, &key).await.status, StatusCode::OK);
    }
    let r = tokens(&app, &house.house_id, &key).await;
    assert_eq!((r.status, reason(&r).as_str()), (StatusCode::TOO_MANY_REQUESTS, "rate_limited"));
    app.clock.advance(chrono::Duration::minutes(1));
    assert_eq!(tokens(&app, &house.house_id, &key).await.status, StatusCode::OK);
}

async fn acme(app: &TestApp, method: Method, house: &str, key: &SigningKey, body: &[u8]) -> common::TestResponse {
    signed(app, method, ACME_PATH, body, house, key, app.clock.unix()).await
}

#[sqlx::test]
async fn acme_put_and_delete(pool: PgPool) {
    let app = TestApp::new(pool);
    let (house, key, _) = enrolled_house(&app, "alice@exemple.fr", 2).await;
    let value = "gfj9Xq-Rq7HvW_8h0vTlV1yUq3dMZ3lQKXyR9_5nHk0";
    let body = serde_json::to_vec(&serde_json::json!({"value": value})).unwrap();
    let r = acme(&app, Method::POST, &house.house_id, &key, &body).await;
    assert_eq!(r.status, StatusCode::NO_CONTENT, "{}", r.text());
    assert_eq!(app.dns.records(), [(format!("_acme-challenge.{}", house.host), value.to_owned())]);
    let r = acme(&app, Method::DELETE, &house.house_id, &key, &body).await;
    assert_eq!(r.status, StatusCode::NO_CONTENT);
    assert!(app.dns.records().is_empty());
}

#[sqlx::test]
async fn acme_bad_value(pool: PgPool) {
    let app = TestApp::new(pool);
    let (house, key, _) = enrolled_house(&app, "alice@exemple.fr", 2).await;
    let long = "a".repeat(256);
    for value in ["", "deux mots", "a\"b", "x.y", long.as_str()] {
        let body = serde_json::to_vec(&serde_json::json!({"value": value})).unwrap();
        let r = acme(&app, Method::POST, &house.house_id, &key, &body).await;
        assert_eq!((r.status, reason(&r).as_str()), (StatusCode::BAD_REQUEST, "bad_request"), "{value:?}");
    }
    let r = acme(&app, Method::POST, &house.house_id, &key, b"{").await;
    assert_eq!(reason(&r), "bad_request");
    assert!(app.dns.records().is_empty());
    // Maison révoquée : plus de certificat.
    admin::revoke_house(&app.state, &house.host).await.unwrap();
    let body = serde_json::to_vec(&serde_json::json!({"value": "abc"})).unwrap();
    let r = acme(&app, Method::POST, &house.house_id, &key, &body).await;
    assert_eq!((r.status, reason(&r).as_str()), (StatusCode::FORBIDDEN, "revoked"));
}

#[sqlx::test]
async fn deleted_account_house_is_revoked(pool: PgPool) {
    let app = TestApp::new(pool);
    let (house, key, session) = enrolled_house(&app, "alice@exemple.fr", 2).await;
    let r = app.request(Method::POST, "/compte/supprimer").session(&session).form(&[("confirmation", "alice@exemple.fr")]).send().await;
    assert_eq!(r.status, StatusCode::SEE_OTHER);
    let r = tokens(&app, &house.house_id, &key).await;
    assert_eq!((r.status, reason(&r).as_str()), (StatusCode::FORBIDDEN, "revoked"));
}

/// La brique du socle n'envoie que `Agendo-Signature` (pas d'`Agendo-House`) : le plan de
/// contrôle retrouve la maison par sa clé.
async fn brick_style(app: &TestApp, method: Method, path: &str, body: &[u8], key: &SigningKey) -> common::TestResponse {
    let signature = agendo_access_protocol::signature::sign_request(key, method.as_str(), path, body, app.clock.unix());
    let mut request = app.request(method, path).header("agendo-signature", &signature);
    if !body.is_empty() {
        request = request.header("content-type", "application/json");
    }
    request.bytes(body.to_vec()).send().await
}

#[sqlx::test]
async fn tokens_without_house_header(pool: PgPool) {
    let app = TestApp::new(pool);
    let (first, first_key, _) = enrolled_house(&app, "alice@exemple.fr", 2).await;
    let (second, second_key, _) = enrolled_house(&app, "bob@exemple.fr", 3).await;
    for (house, key) in [(&first, &first_key), (&second, &second_key)] {
        let r = brick_style(&app, Method::POST, TOKENS_PATH, b"", key).await;
        assert_eq!(r.status, StatusCode::OK, "{}", r.text());
        let tokens: TokensResponse = serde_json::from_slice(&r.body).unwrap();
        let trusted = TrustedKeys::new(app.state.signer.trusted()).unwrap();
        let claims = TunnelClaims::verify(&tokens.tunnel_token, &trusted, app.clock.unix()).unwrap();
        assert_eq!((claims.sub.as_str(), claims.host.as_str()), (house.house_id.as_str(), house.host.as_str()));
    }
    // ACME de la seconde maison : son propre nom d'hôte.
    let body = serde_json::to_vec(&serde_json::json!({"value": "abc"})).unwrap();
    assert_eq!(brick_style(&app, Method::POST, ACME_PATH, &body, &second_key).await.status, StatusCode::NO_CONTENT);
    assert_eq!(app.dns.records()[0].0, format!("_acme-challenge.{}", second.host));
    // Clé inconnue, horloge décalée : refus explicites.
    let r = brick_style(&app, Method::POST, TOKENS_PATH, b"", &SigningKey::from_bytes(&[9; 32])).await;
    assert_eq!((r.status, reason(&r).as_str()), (StatusCode::UNAUTHORIZED, "bad_signature"));
    admin::revoke_house(&app.state, &first.host).await.unwrap();
    let r = brick_style(&app, Method::POST, TOKENS_PATH, b"", &first_key).await;
    assert_eq!((r.status, reason(&r).as_str()), (StatusCode::FORBIDDEN, "revoked"));
}

#[sqlx::test]
async fn acme_keeps_two_values_and_revoked_house_can_clear(pool: PgPool) {
    let app = TestApp::new(pool);
    let (house, key, _) = enrolled_house(&app, "alice@exemple.fr", 2).await;
    let body = |v: &str| serde_json::to_vec(&serde_json::json!({"value": v})).unwrap();
    for value in ["v1", "v2", "v3"] {
        assert_eq!(acme(&app, Method::POST, &house.house_id, &key, &body(value)).await.status, StatusCode::NO_CONTENT);
    }
    let name = format!("_acme-challenge.{}", house.host);
    // Au plus deux valeurs par nom (DNS-01 n'en demande jamais plus) : la plus ancienne part.
    assert_eq!(app.dns.records(), [(name.clone(), "v2".to_owned()), (name.clone(), "v3".to_owned())]);
    // Une maison révoquée peut encore retirer ses TXT, pas en poser.
    admin::revoke_house(&app.state, &house.host).await.unwrap();
    assert_eq!(acme(&app, Method::POST, &house.house_id, &key, &body("v4")).await.status, StatusCode::FORBIDDEN);
    assert_eq!(acme(&app, Method::DELETE, &house.house_id, &key, &body("v2")).await.status, StatusCode::NO_CONTENT);
    assert_eq!(app.dns.records(), [(name, "v3".to_owned())]);
}
