mod common;

use agendo_access_cloud::{config::Config, signing::Signer};
use agendo_access_protocol::{
    SigningKey,
    api::KeysResponse,
    keys::{TrustedKey, TrustedKeys, encode_public_key},
    token::{PushClaims, TOKEN_LIFETIME_SECS, TunnelClaims},
};
use axum::http::StatusCode;
use common::TestApp;
use sqlx::PgPool;

fn public(seed: u8) -> String {
    encode_public_key(&SigningKey::from_bytes(&[seed; 32]).verifying_key())
}

#[sqlx::test]
async fn keys_endpoint_lists_current_and_published(pool: PgPool) {
    let published = vec![TrustedKey { kid: "k0".into(), key: public(9) }];
    let signer = Signer::from_seed([1; 32], "k1", published).unwrap();
    let app = TestApp::build(pool, Config::for_tests(), signer);
    let r = app.get("/.well-known/agendo-access/keys").await;
    assert_eq!(r.status, StatusCode::OK);
    let keys: KeysResponse = serde_json::from_slice(&r.body).unwrap();
    assert_eq!(
        keys.keys,
        [TrustedKey { kid: "k1".into(), key: public(1) }, TrustedKey { kid: "k0".into(), key: public(9) }]
    );
}

#[test]
fn published_kid_must_differ() {
    let same = vec![TrustedKey { kid: "k1".into(), key: public(9) }];
    assert!(Signer::from_seed([1; 32], "k1", same).is_err());
}

#[test]
fn issued_tokens_verify() {
    let config = Config::for_tests();
    let signer = Signer::from_seed([1; 32], "k1", Vec::new()).unwrap();
    let now = 1_793_000_000;
    let tokens = signer.issue("maison-1", "abcdefghijklmnop.maisons.exemple.fr", &public(2), now, &config);
    let trusted = TrustedKeys::new(signer.trusted()).unwrap();
    let tunnel = TunnelClaims::verify(&tokens.tunnel_token, &trusted, now).unwrap();
    assert_eq!(tunnel.iss, "https://api.exemple.fr");
    assert_eq!(tunnel.sub, "maison-1");
    assert_eq!(tunnel.host, "abcdefghijklmnop.maisons.exemple.fr");
    assert_eq!(tunnel.house_key, public(2));
    assert_eq!((tunnel.iat, tunnel.exp), (now, now + TOKEN_LIFETIME_SECS));
    let push = PushClaims::verify(&tokens.push_token, &trusted, now).unwrap();
    assert_eq!(push.quotas, config.quotas);
    assert_eq!(push.house_key, public(2));
    assert_eq!(tokens.expires_at, now + TOKEN_LIFETIME_SECS);
    assert_eq!(tokens.relays, config.relays);
    assert_eq!(tokens.push_urls, config.push_urls);
}

#[test]
fn seed_file_errors() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("cle");
    let vars = |content: Option<&str>| {
        if let Some(content) = content {
            std::fs::write(&path, content).unwrap();
        }
        let path = path.to_string_lossy().into_owned();
        move |name: &str| match name {
            "AGENDO_CLOUD_SIGNING_KEY_FILE" => Some(path.clone()),
            "AGENDO_CLOUD_SIGNING_KID" => Some("k1".into()),
            _ => None,
        }
    };
    let missing = Signer::from_env(&vars(None)).err().unwrap().to_string();
    assert!(missing.contains("AGENDO_CLOUD_SIGNING_KEY_FILE"), "{missing}");
    let bad = Signer::from_env(&vars(Some("graine-secrete-mal-encodee"))).err().unwrap().to_string();
    assert!(bad.contains("AGENDO_CLOUD_SIGNING_KEY_FILE") && !bad.contains("graine-secrete"), "{bad}");
    let seed = agendo_access_protocol::b64(&[1; 32]);
    let signer = Signer::from_env(&vars(Some(&format!("{seed}\n")))).unwrap();
    assert_eq!(signer.trusted(), [TrustedKey { kid: "k1".into(), key: public(1) }]);
}

#[test]
fn keygen_writes_seed_and_refuses_overwrite() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("cle");
    let out = agendo_access_cloud::signing::keygen(&path, "k2").unwrap();
    let seed = std::fs::read_to_string(&path).unwrap();
    assert!(!out.contains(seed.trim()), "la graine ne s'affiche pas");
    let vars = |name: &str| match name {
        "AGENDO_CLOUD_SIGNING_KEY_FILE" => Some(path.to_string_lossy().into_owned()),
        "AGENDO_CLOUD_SIGNING_KID" => Some("k2".into()),
        _ => None,
    };
    let signer = Signer::from_env(&vars).unwrap();
    let line = format!("k2={}", signer.trusted()[0].key);
    assert!(out.contains(&line), "{out}");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
    }
    assert!(agendo_access_cloud::signing::keygen(&path, "k2").is_err());
    assert_eq!(std::fs::read_to_string(&path).unwrap(), seed, "fichier intact");
}
