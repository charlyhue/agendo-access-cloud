mod common;

use agendo_access_cloud::{admin, crypto};
use chrono::{DateTime, Duration, Utc};
use common::TestApp;
use sqlx::PgPool;

/// Jeton d'invitation porté par le lien du dernier e-mail.
fn invitation_token(app: &TestApp) -> String {
    let mail = app.mailer.sent().pop().expect("un e-mail");
    let start = mail.text.find("/invitation/").expect("lien d'invitation") + "/invitation/".len();
    mail.text[start..].split_whitespace().next().unwrap().to_owned()
}

#[sqlx::test]
async fn invite_creates_account_and_mails(pool: PgPool) {
    let app = TestApp::new(pool.clone());
    let out = admin::invite(&app.state, "alice@exemple.fr").await.unwrap();
    assert!(out.contains("alice@exemple.fr"), "{out}");

    let (status, active, source): (String, bool, String) =
        sqlx::query_as("SELECT status, subscription_active, subscription_source FROM accounts WHERE email = 'alice@exemple.fr'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!((status.as_str(), active, source.as_str()), ("invited", true, "manual"));

    let mail = app.mailer.sent().pop().unwrap();
    assert_eq!(mail.to, "alice@exemple.fr");
    assert!(mail.text.contains("https://compte.exemple.fr/invitation/"), "{}", mail.text);
    assert!(mail.html.contains("https://compte.exemple.fr/invitation/"));
    let token = invitation_token(&app);
    let expires: DateTime<Utc> = sqlx::query_scalar("SELECT expires_at FROM invitations WHERE token_hash = $1")
        .bind(crypto::hash(&token))
        .fetch_one(&pool)
        .await
        .expect("jeton haché en base");
    assert_eq!(expires, common::start() + Duration::days(7));
    // Le jeton lui-même n'est nulle part en base.
    let clear: i64 = sqlx::query_scalar("SELECT count(*) FROM invitations WHERE encode(token_hash, 'escape') LIKE '%' || $1 || '%'")
        .bind(&token)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(clear, 0);
}

#[sqlx::test]
async fn invite_normalizes_email(pool: PgPool) {
    let app = TestApp::new(pool.clone());
    admin::invite(&app.state, " Alice@Exemple.FR ").await.unwrap();
    let first = invitation_token(&app);
    admin::invite(&app.state, "alice@exemple.fr").await.unwrap();
    let second = invitation_token(&app);
    assert_ne!(first, second);
    let accounts: i64 = sqlx::query_scalar("SELECT count(*) FROM accounts").fetch_one(&pool).await.unwrap();
    assert_eq!(accounts, 1);
    // Seule la dernière invitation reste utilisable.
    let usable: i64 = sqlx::query_scalar("SELECT count(*) FROM invitations WHERE consumed_at IS NULL")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(usable, 1);
    assert!(admin::invite(&app.state, "pas-une-adresse").await.is_err());
}

#[sqlx::test]
async fn invite_refuses_active(pool: PgPool) {
    let app = TestApp::new(pool.clone());
    admin::invite(&app.state, "alice@exemple.fr").await.unwrap();
    sqlx::query("UPDATE accounts SET status = 'active'").execute(&pool).await.unwrap();
    let err = admin::invite(&app.state, "alice@exemple.fr").await.unwrap_err();
    assert!(err.to_string().contains("déjà actif"), "{err}");
}

#[sqlx::test]
async fn suspend_resume(pool: PgPool) {
    let app = TestApp::new(pool.clone());
    admin::invite(&app.state, "alice@exemple.fr").await.unwrap();
    let active = || async { sqlx::query_scalar::<_, bool>("SELECT subscription_active FROM accounts").fetch_one(&pool).await.unwrap() };
    admin::suspend(&app.state, "ALICE@exemple.fr").await.unwrap();
    assert!(!active().await);
    admin::resume(&app.state, "alice@exemple.fr").await.unwrap();
    assert!(active().await);
    assert!(admin::suspend(&app.state, "bob@exemple.fr").await.is_err());
    let events: Vec<String> = sqlx::query_scalar("SELECT event FROM audit ORDER BY id").fetch_all(&pool).await.unwrap();
    assert_eq!(events, ["invitation_sent", "subscription_suspended", "subscription_resumed"]);
}

#[sqlx::test]
async fn list_shows_accounts(pool: PgPool) {
    let app = TestApp::new(pool.clone());
    assert!(admin::list(&app.state).await.unwrap().contains("aucun compte"));
    admin::invite(&app.state, "alice@exemple.fr").await.unwrap();
    admin::invite(&app.state, "bob@exemple.fr").await.unwrap();
    admin::suspend(&app.state, "bob@exemple.fr").await.unwrap();
    let out = admin::list(&app.state).await.unwrap();
    let alice = out.lines().find(|l| l.contains("alice@exemple.fr")).unwrap();
    let bob = out.lines().find(|l| l.contains("bob@exemple.fr")).unwrap();
    assert!(alice.contains("invité") && alice.contains("actif") && alice.contains(" 0"), "{alice}");
    assert!(bob.contains("suspendu"), "{bob}");
}
