//! Parcours complet : invitation, passkey, rattachement, jetons, ACME, suspension, révocation.
mod common;

use agendo_access_cloud::{admin, clock::Clock};
use agendo_access_protocol::{
    SigningKey,
    api::{ACME_PATH, EnrollResponse, KEYS_PATH, KeysResponse, TOKENS_PATH, TokensResponse, host_in_zone},
    keys::TrustedKeys,
    token::{PushClaims, TunnelClaims},
};
use agendo_webauthn::soft::Authenticator;
use axum::http::{Method, StatusCode};
use common::{TestApp, enroll, enrollment_code, invite, register_invitation, signed};
use sqlx::PgPool;

#[sqlx::test]
async fn end_to_end(pool: PgPool) {
    let app = TestApp::new(pool);

    // La personne invitée crée sa passkey par le lien reçu.
    let token = invite(&app, "alice@exemple.fr").await;
    let registered = register_invitation(&app, &token, &Authenticator::new(1)).await;
    assert_eq!(registered.status, StatusCode::OK);
    let session = registered.session_cookie().unwrap();

    // Elle rattache sa maison avec le code du portail ; la maison a généré sa clé.
    let code = enrollment_code(&app, &session).await;
    let house_key = SigningKey::from_bytes(&[2; 32]);
    let house: EnrollResponse = serde_json::from_slice(&enroll(&app, &code, 2, "Maison principale").await.body).unwrap();
    assert!(host_in_zone(&house.host, &app.state.config.zone));

    // La maison obtient ses jetons, vérifiables avec les clés publiées.
    let keys: KeysResponse = serde_json::from_slice(&app.get(KEYS_PATH).await.body).unwrap();
    assert_eq!(keys.keys, house.trusted_keys);
    let trusted = TrustedKeys::new(keys.keys).unwrap();
    let tokens = || signed(&app, Method::POST, TOKENS_PATH, b"", &house.house_id, &house_key, app.clock.unix());
    let issued: TokensResponse = serde_json::from_slice(&tokens().await.body).unwrap();
    let tunnel = TunnelClaims::verify(&issued.tunnel_token, &trusted, app.clock.unix()).unwrap();
    assert_eq!(tunnel.host, house.host);
    assert_eq!(tunnel.house_key().unwrap(), house_key.verifying_key());
    PushClaims::verify(&issued.push_token, &trusted, app.clock.unix()).unwrap();

    // Défi ACME DNS-01 de son certificat.
    let body = serde_json::to_vec(&serde_json::json!({"value": "condense-acme_43-caracteres-environ-xxxxxxx"})).unwrap();
    let r = signed(&app, Method::POST, ACME_PATH, &body, &house.house_id, &house_key, app.clock.unix()).await;
    assert_eq!(r.status, StatusCode::NO_CONTENT);
    assert_eq!(app.dns.records()[0].0, format!("_acme-challenge.{}", house.host));

    // Abonnement suspendu, puis rétabli.
    admin::suspend(&app.state, "alice@exemple.fr").await.unwrap();
    let r = tokens().await;
    assert_eq!((r.status, r.json()["reason"].as_str()), (StatusCode::FORBIDDEN, Some("subscription_inactive")));
    admin::resume(&app.state, "alice@exemple.fr").await.unwrap();
    assert_eq!(tokens().await.status, StatusCode::OK);

    // Maison révoquée par l'administration.
    admin::revoke_house(&app.state, &house.host).await.unwrap();
    let r = tokens().await;
    assert_eq!((r.status, r.json()["reason"].as_str()), (StatusCode::FORBIDDEN, Some("revoked")));
    let page = app.request(Method::GET, "/maisons").session(&session).send().await.text();
    assert!(page.contains("Révoquée"));
}
