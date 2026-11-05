//! Outils communs aux tests d'intégration : application de test, requêtes, réponses.
#![allow(dead_code)]

use std::sync::Arc;

#[allow(unused_imports)]
pub use agendo_access_cloud::clock::Clock;

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
        Self::build(pool, config, Signer::from_seed([1; 32], "k1", Vec::new()).unwrap())
    }

    pub fn build(pool: PgPool, config: Config, signer: Signer) -> Self {
        let clock = Arc::new(ManualClock::new(start()));
        let mailer = Arc::new(MemoryMailer::default());
        let dns = Arc::new(FakeDns::default());
        let signer = Arc::new(signer);
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

    /// E-mails envoyés, une fois les envois en tâche de fond achevés.
    pub async fn sent(&self) -> Vec<agendo_access_cloud::mail::Mail> {
        tokio::time::sleep(std::time::Duration::from_millis(30)).await;
        self.mailer.sent()
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

/// Code à 6 chiffres du dernier e-mail envoyé (le code part en tâche de fond).
pub async fn last_code(app: &TestApp) -> String {
    let mail = app.sent().await.pop().expect("un e-mail");
    let start = mail.text.find(" : ").expect("code dans l'e-mail") + 3;
    mail.text[start..start + 6].to_owned()
}

/// Connexion par code e-mail ; rend le jeton de session.
pub async fn login(app: &TestApp, email: &str) -> String {
    let r = app.request(Method::POST, "/connexion/code").form(&[("email", email)]).send().await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
    let code = last_code(app).await;
    let r = app.request(Method::POST, "/connexion/code/verifier").form(&[("email", email), ("code", &code)]).send().await;
    assert_eq!(r.status, StatusCode::SEE_OTHER, "{}", r.text());
    r.session_cookie().expect("cookie de session")
}

pub const RP_ID: &str = "compte.exemple.fr";
pub const ORIGIN: &str = "https://compte.exemple.fr";

/// Invite `email` par la commande d'administration ; rend le jeton du lien envoyé.
pub async fn invite(app: &TestApp, email: &str) -> String {
    agendo_access_cloud::admin::invite(&app.state, email).await.unwrap();
    let mail = app.mailer.sent().pop().expect("e-mail d'invitation");
    let start = mail.text.find("/invitation/").unwrap() + "/invitation/".len();
    mail.text[start..].split_whitespace().next().unwrap().to_owned()
}

/// Enregistre une passkey de `authenticator` par le lien d'invitation (cérémonie complète).
pub async fn register_invitation(app: &TestApp, token: &str, authenticator: &agendo_webauthn::soft::Authenticator) -> TestResponse {
    let options = app.request(Method::POST, &format!("/invitation/{token}/options")).json(&serde_json::json!({})).send().await;
    assert_eq!(options.status, StatusCode::OK, "{}", options.text());
    let challenge = options.json()["challenge"].as_str().unwrap().to_owned();
    let credential = authenticator.register(RP_ID, ORIGIN, &challenge);
    app.request(Method::POST, &format!("/invitation/{token}/terminer"))
        .json(&serde_json::json!({"credential": credential, "name": "iPhone"}))
        .send()
        .await
}

/// Compte invité puis activé par passkey ; rend la session ouverte et l'authentificateur.
pub async fn onboard(app: &TestApp, email: &str, seed: u8) -> (String, agendo_webauthn::soft::Authenticator) {
    let token = invite(app, email).await;
    let authenticator = agendo_webauthn::soft::Authenticator::new(seed);
    let r = register_invitation(app, &token, &authenticator).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
    (r.session_cookie().expect("session ouverte"), authenticator)
}

/// Connexion par passkey (cérémonie complète).
pub async fn passkey_login(app: &TestApp, authenticator: &mut agendo_webauthn::soft::Authenticator) -> TestResponse {
    let options = app.request(Method::POST, "/connexion/passkey/options").json(&serde_json::json!({})).send().await;
    assert_eq!(options.status, StatusCode::OK, "{}", options.text());
    let challenge = options.json()["challenge"].as_str().unwrap().to_owned();
    let credential = authenticator.assert(RP_ID, ORIGIN, &challenge);
    app.request(Method::POST, "/connexion/passkey/terminer").json(&serde_json::json!({"credential": credential})).send().await
}

/// Maison rattachée directement en base au compte (étiquette `label`, clé de graine `seed`).
pub async fn insert_house(app: &TestApp, account: uuid::Uuid, label: &str, seed: u8) -> uuid::Uuid {
    use agendo_access_protocol::{SigningKey, keys::encode_public_key};
    let id = uuid::Uuid::new_v4();
    let key = encode_public_key(&SigningKey::from_bytes(&[seed; 32]).verifying_key());
    sqlx::query(
        "INSERT INTO houses (id, account_id, label, host, name, public_key, enrolled_at) VALUES ($1, $2, $3, $4, 'Maison', $5, $6)",
    )
    .bind(id)
    .bind(account)
    .bind(label)
    .bind(format!("{label}.maisons.exemple.fr"))
    .bind(key)
    .bind(start())
    .execute(&app.state.db)
    .await
    .unwrap();
    id
}

/// Identifiant du compte de cette adresse.
pub async fn account_id(app: &TestApp, email: &str) -> uuid::Uuid {
    sqlx::query_scalar("SELECT id FROM accounts WHERE email = $1").bind(email).fetch_one(&app.state.db).await.unwrap()
}

/// Code de rattachement affiché par le portail (`XXXX-XXXX`).
pub async fn enrollment_code(app: &TestApp, session: &str) -> String {
    let r = app.request(Method::POST, "/maisons/rattacher").session(session).form(&[]).send().await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
    let text = r.text();
    let start = text.find("class=\"code\">").expect("code affiché") + "class=\"code\">".len();
    text[start..].split('<').next().unwrap().trim().to_owned()
}

/// `POST /v1/houses/enroll` avec la clé de maison de graine `seed`.
pub async fn enroll(app: &TestApp, code: &str, seed: u8, name: &str) -> TestResponse {
    use agendo_access_protocol::{SigningKey, keys::encode_public_key};
    let key = encode_public_key(&SigningKey::from_bytes(&[seed; 32]).verifying_key());
    app.request(Method::POST, agendo_access_protocol::api::ENROLL_PATH)
        .json(&serde_json::json!({"code": code, "house_key": key, "name": name}))
        .send()
        .await
}

/// Maison rattachée de bout en bout (invitation, passkey, code, enroll) avec la clé de
/// graine `seed` ; rend la réponse du rattachement, la clé et la session du compte.
pub async fn enrolled_house(app: &TestApp, email: &str, seed: u8) -> (agendo_access_protocol::api::EnrollResponse, agendo_access_protocol::SigningKey, String) {
    let (session, _) = onboard(app, email, seed).await;
    let code = enrollment_code(app, &session).await;
    let r = enroll(app, &code, seed, "Maison").await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
    (serde_json::from_slice(&r.body).unwrap(), agendo_access_protocol::SigningKey::from_bytes(&[seed; 32]), session)
}

/// Requête signée par la maison : `Agendo-Signature: house=<house_id>,t=<t>,sig=…`.
pub async fn signed(
    app: &TestApp,
    method: Method,
    path: &str,
    body: &[u8],
    house_id: &str,
    key: &agendo_access_protocol::SigningKey,
    t: i64,
) -> TestResponse {
    let signature = agendo_access_protocol::signature::sign_request(key, house_id, method.as_str(), path, body, t);
    let mut request = app.request(method, path).header("agendo-signature", &signature);
    if !body.is_empty() {
        request = request.header("content-type", "application/json");
    }
    request.bytes(body.to_vec()).send().await
}
