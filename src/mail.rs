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
