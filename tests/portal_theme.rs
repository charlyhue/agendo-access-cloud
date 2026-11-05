//! Thème du portail : celui de l'interface des maisons (socle, `ui/src/index.css` et la page de
//! connexion de la passerelle), sombre seulement, polices système, rien de tiers.
mod common;

use axum::http::StatusCode;
use common::TestApp;
use sqlx::PgPool;

#[sqlx::test]
async fn stylesheet_carries_house_tokens(pool: PgPool) {
    let app = TestApp::new(pool);
    let css = app.get("/static/portail.css").await.text();
    for token in [
        "--color-accent-light: #f6b100",
        "--color-bad: #ff453a",
        "--agendo-glass-background:",
        "--agendo-sheet-radius: 28px",
        "-apple-system, BlinkMacSystemFont, 'SF Pro Text', 'Inter', 'Segoe UI', Roboto, system-ui, sans-serif",
        "color-scheme: dark",
    ] {
        assert!(css.contains(token), "{token} absent de portail.css");
    }
    // Sombre seulement, comme l'interface des maisons ; aucune ressource extérieure.
    assert!(!css.contains("prefers-color-scheme"));
    assert!(!css.contains("@import") && !css.contains("url(http") && !css.contains("@font-face"));
}

#[sqlx::test]
async fn pages_declare_dark_scheme_and_local_icon(pool: PgPool) {
    let app = TestApp::new(pool);
    let page = app.get("/connexion").await.text();
    assert!(page.contains(r#"<meta name="color-scheme" content="dark">"#), "{page}");
    assert!(page.contains(r#"href="/static/favicon.svg""#));
    let icon = app.get("/static/favicon.svg").await;
    assert_eq!(icon.status, StatusCode::OK);
    assert!(icon.headers.get("content-type").unwrap().to_str().unwrap().starts_with("image/svg+xml"));
    // Feuille et script revalidés à chaque chargement : un déploiement se voit tout de suite.
    for path in ["/static/portail.css", "/static/webauthn.js"] {
        assert_eq!(app.get(path).await.headers.get("cache-control").unwrap(), "no-cache", "{path}");
    }
    // La CSP ne s'ouvre à aucune autre origine.
    let csp = app.get("/connexion").await.headers.get("content-security-policy").unwrap().to_str().unwrap().to_owned();
    assert!(!csp.contains("http") && !csp.contains("data:"), "{csp}");
}
