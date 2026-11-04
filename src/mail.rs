//! Envoi des e-mails (invitations, codes de connexion).
//!
//! `ResendMailer` en production, `OutboxMailer` en développement (fichiers dans un dossier
//! local), `MemoryMailer` dans les tests. Le contenu d'un e-mail porte un secret (lien
//! d'invitation, code) : il n'est jamais journalisé.

use std::sync::Mutex;

use async_trait::async_trait;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mail {
    pub to: String,
    pub subject: String,
    pub text: String,
    pub html: String,
}

#[async_trait]
pub trait Mailer: Send + Sync {
    async fn send(&self, mail: Mail) -> anyhow::Result<()>;
}

/// Garde les e-mails en mémoire (tests).
#[derive(Default)]
pub struct MemoryMailer(Mutex<Vec<Mail>>);

impl MemoryMailer {
    pub fn sent(&self) -> Vec<Mail> {
        self.0.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }
}

#[async_trait]
impl Mailer for MemoryMailer {
    async fn send(&self, mail: Mail) -> anyhow::Result<()> {
        self.0.lock().unwrap_or_else(|e| e.into_inner()).push(mail);
        Ok(())
    }
}

/// Resend (`POST {api_url}/emails`). Une erreur ne cite que le statut : la réponse peut
/// reprendre l'adresse ou le contenu.
pub struct ResendMailer {
    client: reqwest::Client,
    endpoint: String,
    key: String,
    from: String,
}

impl ResendMailer {
    pub fn new(api_url: &str, key: String, from: String) -> Self {
        let endpoint = format!("{}/emails", api_url.trim_end_matches('/'));
        Self { client: crate::http::client(), endpoint, key, from }
    }
}

#[async_trait]
impl Mailer for ResendMailer {
    async fn send(&self, mail: Mail) -> anyhow::Result<()> {
        let body = serde_json::json!({
            "from": self.from,
            "to": [mail.to],
            "subject": mail.subject,
            "text": mail.text,
            "html": mail.html,
        });
        let response = self
            .client
            .post(&self.endpoint)
            .bearer_auth(&self.key)
            .json(&body)
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("Resend injoignable : {}", e.without_url()))?;
        let status = response.status();
        if !status.is_success() {
            anyhow::bail!("Resend refuse l'envoi (statut {})", status.as_u16());
        }
        Ok(())
    }
}

/// Boîte d'envoi de développement : un fichier texte par e-mail dans un dossier local.
pub struct OutboxMailer {
    dir: std::path::PathBuf,
    counter: std::sync::atomic::AtomicU64,
}

impl OutboxMailer {
    pub fn new(dir: std::path::PathBuf) -> Self {
        Self { dir, counter: Default::default() }
    }
}

#[async_trait]
impl Mailer for OutboxMailer {
    async fn send(&self, mail: Mail) -> anyhow::Result<()> {
        tokio::fs::create_dir_all(&self.dir).await?;
        let n = self.counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let name = format!("{}-{n}.txt", chrono::Utc::now().format("%Y%m%dT%H%M%S%.6f"));
        let content = format!("À : {}\nSujet : {}\n\n{}\n", mail.to, mail.subject, mail.text);
        tokio::fs::write(self.dir.join(name), content).await?;
        Ok(())
    }
}

/// Expéditeur selon `AGENDO_CLOUD_MAILER` : `resend` (production) ou `outbox` (développement).
pub fn from_env(vars: &dyn crate::config::Vars) -> Result<std::sync::Arc<dyn Mailer>, crate::config::ConfigError> {
    use crate::config::{ConfigError, read_secret_file};
    match vars.required("AGENDO_CLOUD_MAILER")?.as_str() {
        "resend" => {
            let api_url = vars.var("AGENDO_CLOUD_RESEND_API_URL").unwrap_or_else(|| "https://api.resend.com".into());
            let key = read_secret_file(vars, "AGENDO_CLOUD_RESEND_API_KEY_FILE")?;
            let from = vars.required("AGENDO_CLOUD_MAIL_FROM")?;
            Ok(std::sync::Arc::new(ResendMailer::new(api_url.trim(), key, from)))
        }
        "outbox" => Ok(std::sync::Arc::new(OutboxMailer::new(vars.required("AGENDO_CLOUD_OUTBOX_DIR")?.into()))),
        other => Err(ConfigError::Invalid {
            name: "AGENDO_CLOUD_MAILER".into(),
            reason: format!("{other:?} : resend ou outbox attendu"),
        }),
    }
}

/// Échappement HTML minimal des textes insérés dans les e-mails.
fn escape(text: &str) -> String {
    text.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

/// E-mail d'invitation : lien à usage unique vers l'enregistrement d'une passkey.
pub fn invitation(to: &str, link: &str) -> Mail {
    let text = format!(
        "Bonjour,\n\nUne invitation à Agendo Access vous attend. Ouvrez ce lien pour créer votre \
         passkey et activer votre compte (valable 7 jours, une seule fois) :\n\n{link}\n\n\
         Si vous n'attendiez pas cette invitation, ignorez ce message.\n"
    );
    let link = escape(link);
    let html = format!(
        "<p>Bonjour,</p><p>Une invitation à Agendo Access vous attend. Ouvrez ce lien pour créer \
         votre passkey et activer votre compte (valable 7 jours, une seule fois) :</p>\
         <p><a href=\"{link}\">{link}</a></p>\
         <p>Si vous n'attendiez pas cette invitation, ignorez ce message.</p>"
    );
    Mail { to: to.to_owned(), subject: "Votre invitation à Agendo Access".into(), text, html }
}

/// E-mail du code de connexion de secours.
pub fn login_code(to: &str, code: &str) -> Mail {
    let text = format!(
        "Votre code de connexion à Agendo Access : {code}\n\nIl est valable 10 minutes. Si vous \
         n'avez pas demandé ce code, ignorez ce message : sans lui, personne ne peut se connecter.\n"
    );
    let html = format!(
        "<p>Votre code de connexion à Agendo Access :</p><p style=\"font-size:1.6em;letter-spacing:0.2em\"><strong>{}</strong></p>\
         <p>Il est valable 10 minutes. Si vous n'avez pas demandé ce code, ignorez ce message : \
         sans lui, personne ne peut se connecter.</p>",
        escape(code)
    );
    Mail { to: to.to_owned(), subject: format!("Code de connexion Agendo Access : {code}"), text, html }
}
