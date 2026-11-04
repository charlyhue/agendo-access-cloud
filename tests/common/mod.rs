//! Outils communs aux tests d'intégration : application de test, requêtes, réponses.
#![allow(dead_code)]

use std::sync::Arc;

use agendo_access_cloud::{
    AppState, app,
    clock::ManualClock,
    config::Config,
    dns::FakeDns,
    mail::MemoryMailer,
    signing::Signer,
};
use axum::{
    Router,
    body::Body,
    http::{HeaderMap, Method, Request, StatusCode, header},
};
use chrono::{DateTime, TimeZone, Utc};
use http_body_util::BodyExt;
use sqlx::PgPool;
use tower::ServiceExt;

/// Instant de départ de l'horloge des tests.
pub fn start() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 11, 4, 12, 0, 0).unwrap()
}

pub struct TestApp {
    pub state: AppState,
    pub clock: Arc<ManualClock>,
    pub mailer: Arc<MemoryMailer>,
    pub dns: Arc<FakeDns>,
    router: Router,
}

impl TestApp {
    pub fn new(pool: PgPool) -> Self {
        Self::with_config(pool, Config::for_tests())
    }

    pub fn with_config(pool: PgPool, config: Config) -> Self {
        let clock = Arc::new(ManualClock::new(start()));
        let mailer = Arc::new(MemoryMailer::default());
        let dns = Arc::new(FakeDns::default());
        let signer = Arc::new(Signer::from_seed([1; 32], "k1", Vec::new()).unwrap());
        let state = AppState {
            db: pool,
            config: Arc::new(config),
            clock: clock.clone(),
            mailer: mailer.clone(),
            dns: dns.clone(),
            signer,
        };
        let router = app(state.clone());
        Self { state, clock, mailer, dns, router }
    }

    pub fn request(&self, method: Method, path: &str) -> TestRequest<'_> {
        let builder = Request::builder().method(method.clone()).uri(path);
        // Le portail exige l'origine du portail sur toute requête qui n'est pas un GET.
        let builder = if method == Method::GET {
            builder
        } else {
            builder.header(header::ORIGIN, self.state.config.portal_origin())
        };
        TestRequest { app: self, builder, body: Body::empty() }
    }

    pub async fn get(&self, path: &str) -> TestResponse {
        self.request(Method::GET, path).send().await
    }
}

pub struct TestRequest<'a> {
    app: &'a TestApp,
    builder: axum::http::request::Builder,
    body: Body,
}

impl TestRequest<'_> {
    /// Pose l'en-tête `name`, en remplaçant une valeur déjà posée (l'`Origin` par défaut).
    pub fn header(mut self, name: &str, value: &str) -> Self {
        let headers = self.builder.headers_mut().expect("requête valide");
        headers.insert(
            axum::http::HeaderName::from_bytes(name.as_bytes()).unwrap(),
            axum::http::HeaderValue::from_str(value).unwrap(),
        );
        self
    }

    /// Cookie de session (`valeur` seule).
    pub fn session(self, token: &str) -> Self {
        let cookie = format!("{}={token}", agendo_access_cloud::portal::session::COOKIE);
        self.header("cookie", &cookie)
    }

    pub fn form(mut self, fields: &[(&str, &str)]) -> Self {
        let body = fields
            .iter()
            .map(|(k, v)| format!("{}={}", urlencode(k), urlencode(v)))
            .collect::<Vec<_>>()
            .join("&");
        self.builder = self.builder.header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
        self.body = Body::from(body);
        self
    }

    pub fn json(mut self, value: &serde_json::Value) -> Self {
        self.builder = self.builder.header(header::CONTENT_TYPE, "application/json");
        self.body = Body::from(serde_json::to_vec(value).unwrap());
        self
    }

    pub fn bytes(mut self, body: Vec<u8>) -> Self {
        self.body = Body::from(body);
        self
    }

    pub async fn send(self) -> TestResponse {
        let request = self.builder.body(self.body).unwrap();
        let response = self.app.router.clone().oneshot(request).await.unwrap();
        let status = response.status();
        let headers = response.headers().clone();
        let body = response.into_body().collect().await.unwrap().to_bytes().to_vec();
        TestResponse { status, headers, body }
    }
}

fn urlencode(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => (b as char).to_string(),
            b' ' => "+".into(),
            _ => format!("%{b:02X}"),
        })
        .collect()
}

#[derive(Debug)]
pub struct TestResponse {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: Vec<u8>,
}

impl TestResponse {
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }

    pub fn json(&self) -> serde_json::Value {
        serde_json::from_slice(&self.body).unwrap_or_else(|e| panic!("JSON attendu ({e}) : {}", self.text()))
    }

    pub fn location(&self) -> Option<&str> {
        self.headers.get(header::LOCATION).and_then(|v| v.to_str().ok())
    }

    /// Valeur du cookie de session posé par la réponse, s'il y en a un (vide s'il est effacé).
    pub fn session_cookie(&self) -> Option<String> {
        let prefix = format!("{}=", agendo_access_cloud::portal::session::COOKIE);
        self.headers
            .get_all(header::SET_COOKIE)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .find_map(|v| v.strip_prefix(&prefix).map(|rest| rest.split(';').next().unwrap_or("").to_owned()))
    }
}

/// Compte actif créé directement en base (sans passer par l'invitation).
pub async fn active_account(app: &TestApp, email: &str) -> uuid::Uuid {
    let id = uuid::Uuid::new_v4();
    sqlx::query(
        "INSERT INTO accounts (id, email, status, subscription_active, subscription_source, webauthn_user_id, created_at, activated_at)
         VALUES ($1, $2, 'active', true, 'manual', $3, $4, $4)",
    )
    .bind(id)
    .bind(email)
    .bind(id.as_bytes().to_vec())
    .bind(start())
    .execute(&app.state.db)
    .await
    .unwrap();
    id
}

/// Code à 6 chiffres du dernier e-mail envoyé.
pub fn last_code(app: &TestApp) -> String {
    let mail = app.mailer.sent().pop().expect("un e-mail");
    let start = mail.text.find(" : ").expect("code dans l'e-mail") + 3;
    mail.text[start..start + 6].to_owned()
}

/// Connexion par code e-mail ; rend le jeton de session.
pub async fn login(app: &TestApp, email: &str) -> String {
    let r = app.request(Method::POST, "/connexion/code").form(&[("email", email)]).send().await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
    let code = last_code(app);
    let r = app.request(Method::POST, "/connexion/code/verifier").form(&[("email", email), ("code", &code)]).send().await;
    assert_eq!(r.status, StatusCode::SEE_OTHER, "{}", r.text());
    r.session_cookie().expect("cookie de session")
}
