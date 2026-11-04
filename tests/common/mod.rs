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
    pub fn header(mut self, name: &str, value: &str) -> Self {
        self.builder = self.builder.header(name, value);
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
