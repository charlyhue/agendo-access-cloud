mod common;

use axum::http::{Method, StatusCode};
use chrono::Duration;
use common::{TestApp, active_account, last_code, login};
use sqlx::PgPool;

async fn ask_code(app: &TestApp, email: &str) -> common::TestResponse {
    app.request(Method::POST, "/connexion/code").form(&[("email", email)]).send().await
}

async fn verify(app: &TestApp, email: &str, code: &str) -> common::TestResponse {
    app.request(Method::POST, "/connexion/code/verifier").form(&[("email", email), ("code", code)]).send().await
}

#[sqlx::test]
async fn login_page_without_session(pool: PgPool) {
    let app = TestApp::new(pool);
    let r = app.get("/maisons").await;
    assert_eq!(r.status, StatusCode::SEE_OTHER);
    assert_eq!(r.location(), Some("/connexion"));
    let r = app.get("/connexion").await;
    assert_eq!(r.status, StatusCode::OK);
    assert!(r.text().contains("Connexion"));
}

#[sqlx::test]
async fn code_login_flow(pool: PgPool) {
    let app = TestApp::new(pool.clone());
    active_account(&app, "alice@exemple.fr").await;
    let r = ask_code(&app, "alice@exemple.fr").await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(app.mailer.sent().len(), 1);
    let code = last_code(&app);
    let r = verify(&app, "alice@exemple.fr", &code).await;
    assert_eq!(r.status, StatusCode::SEE_OTHER);
    assert_eq!(r.location(), Some("/maisons"));
    let set_cookie = r.headers.get("set-cookie").unwrap().to_str().unwrap();
    for attr in ["Secure", "HttpOnly", "SameSite=Lax", "Path=/", "Max-Age=2592000"] {
        assert!(set_cookie.contains(attr), "{set_cookie}");
    }
    let token = r.session_cookie().unwrap();
    let hashed: i64 = sqlx::query_scalar("SELECT count(*) FROM sessions WHERE token_hash = sha256($1::text::bytea)")
        .bind(&token)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(hashed, 1, "session hachée en base");
    let r = app.request(Method::GET, "/maisons").session(&token).send().await;
    assert_eq!(r.status, StatusCode::OK);
    // Le code ne sert qu'une fois.
    assert_eq!(verify(&app, "alice@exemple.fr", &code).await.status, StatusCode::UNAUTHORIZED);
}

#[sqlx::test]
async fn code_login_ignores_case(pool: PgPool) {
    let app = TestApp::new(pool);
    active_account(&app, "alice@exemple.fr").await;
    ask_code(&app, "  ALICE@Exemple.fr").await;
    let code = last_code(&app);
    assert_eq!(verify(&app, "Alice@exemple.FR", &code).await.status, StatusCode::SEE_OTHER);
}

#[sqlx::test]
async fn unknown_email_same_answer(pool: PgPool) {
    let app = TestApp::new(pool.clone());
    active_account(&app, "alice@exemple.fr").await;
    // Compte encore invité : pas de code non plus.
    sqlx::query("INSERT INTO accounts (id, email, status, subscription_active, subscription_source, webauthn_user_id, created_at)
                 VALUES (gen_random_uuid(), 'bob@exemple.fr', 'invited', true, 'manual', '\\x01', now())")
        .execute(&pool)
        .await
        .unwrap();
    let known = ask_code(&app, "alice@exemple.fr").await;
    let unknown = ask_code(&app, "inconnu@exemple.fr").await;
    let invited = ask_code(&app, "bob@exemple.fr").await;
    assert_eq!(app.mailer.sent().len(), 1);
    for r in [&unknown, &invited] {
        assert_eq!(r.status, known.status);
        assert_eq!(
            r.text().replace("inconnu@exemple.fr", "X").replace("bob@exemple.fr", "X"),
            known.text().replace("alice@exemple.fr", "X")
        );
    }
}

#[sqlx::test]
async fn code_expires_after_10_min(pool: PgPool) {
    let app = TestApp::new(pool);
    active_account(&app, "alice@exemple.fr").await;
    ask_code(&app, "alice@exemple.fr").await;
    let code = last_code(&app);
    app.clock.advance(Duration::minutes(10));
    assert_eq!(verify(&app, "alice@exemple.fr", &code).await.status, StatusCode::UNAUTHORIZED);
}

#[sqlx::test]
async fn code_five_attempts(pool: PgPool) {
    let app = TestApp::new(pool);
    active_account(&app, "alice@exemple.fr").await;
    ask_code(&app, "alice@exemple.fr").await;
    let code = last_code(&app);
    let wrong = if code == "000000" { "111111" } else { "000000" };
    for _ in 0..5 {
        let r = verify(&app, "alice@exemple.fr", wrong).await;
        assert_eq!(r.status, StatusCode::UNAUTHORIZED);
        assert!(r.text().contains("Code incorrect"), "{}", r.text());
    }
    assert_eq!(verify(&app, "alice@exemple.fr", &code).await.status, StatusCode::UNAUTHORIZED);
}

#[sqlx::test]
async fn code_rate_limited(pool: PgPool) {
    let app = TestApp::new(pool);
    active_account(&app, "alice@exemple.fr").await;
    // Configuration de test : 5 codes par heure et par compte.
    for _ in 0..7 {
        assert_eq!(ask_code(&app, "alice@exemple.fr").await.status, StatusCode::OK);
    }
    assert_eq!(app.mailer.sent().len(), 5);
    app.clock.advance(Duration::hours(1));
    ask_code(&app, "alice@exemple.fr").await;
    assert_eq!(app.mailer.sent().len(), 6);
    // 30 cérémonies par minute et par IP.
    let mut last = StatusCode::OK;
    for _ in 0..30 {
        last = ask_code(&app, "inconnu@exemple.fr").await.status;
    }
    assert_eq!(last, StatusCode::TOO_MANY_REQUESTS);
}

#[sqlx::test]
async fn cross_origin_post_refused(pool: PgPool) {
    let app = TestApp::new(pool);
    active_account(&app, "alice@exemple.fr").await;
    for origin in ["https://evil.example", "null", "http://compte.exemple.fr"] {
        let r = app
            .request(Method::POST, "/connexion/code")
            .header("origin", origin)
            .form(&[("email", "alice@exemple.fr")])
            .send()
            .await;
        assert_eq!(r.status, StatusCode::FORBIDDEN, "{origin}");
    }
    assert!(app.mailer.sent().is_empty());
}

#[sqlx::test]
async fn logout_revokes_session(pool: PgPool) {
    let app = TestApp::new(pool);
    active_account(&app, "alice@exemple.fr").await;
    let token = login(&app, "alice@exemple.fr").await;
    let r = app.request(Method::POST, "/deconnexion").session(&token).send().await;
    assert_eq!(r.status, StatusCode::SEE_OTHER);
    assert_eq!(r.session_cookie().as_deref(), Some(""));
    let r = app.request(Method::GET, "/maisons").session(&token).send().await;
    assert_eq!(r.status, StatusCode::SEE_OTHER);
}

#[sqlx::test]
async fn session_expires_after_30_days(pool: PgPool) {
    let app = TestApp::new(pool);
    active_account(&app, "alice@exemple.fr").await;
    let token = login(&app, "alice@exemple.fr").await;
    app.clock.advance(Duration::days(30));
    let r = app.request(Method::GET, "/maisons").session(&token).send().await;
    assert_eq!(r.status, StatusCode::SEE_OTHER);
}

#[sqlx::test]
async fn security_headers_present(pool: PgPool) {
    let app = TestApp::new(pool);
    let r = app.get("/connexion").await;
    let csp = r.headers.get("content-security-policy").unwrap().to_str().unwrap();
    assert!(csp.contains("script-src 'self'") && csp.contains("frame-ancestors 'none'"), "{csp}");
    assert_eq!(r.headers.get("x-content-type-options").unwrap(), "nosniff");
    // `no-referrer` ferait partir les formulaires avec `Origin: null` (standard Fetch) : refusés.
    assert_eq!(r.headers.get("referrer-policy").unwrap(), "same-origin");
    assert_eq!(r.headers.get("cache-control").unwrap(), "no-store");
    let css = app.get("/static/portail.css").await;
    assert_eq!(css.status, StatusCode::OK);
    assert!(css.headers.get("content-type").unwrap().to_str().unwrap().starts_with("text/css"));
}
