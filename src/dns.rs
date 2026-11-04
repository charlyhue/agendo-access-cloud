//! Fournisseur DNS des défis ACME DNS-01 : poser et retirer un TXT `_acme-challenge.<hôte>`.
//!
//! `FakeDns` pour les tests et le développement ; `CloudflareDns` en production *(choix de
//! conception de la spec, à remplacer si la personne choisit un autre fournisseur)*.

use std::sync::Mutex;

use async_trait::async_trait;

#[async_trait]
pub trait DnsProvider: Send + Sync {
    /// Pose un enregistrement TXT `name` de valeur `value` (nom complet, sans point final).
    async fn put_txt(&self, name: &str, value: &str) -> anyhow::Result<()>;
    /// Retire l'enregistrement TXT `name` de valeur `value` ; absent, ce n'est pas une erreur.
    async fn delete_txt(&self, name: &str, value: &str) -> anyhow::Result<()>;
}

/// Zone en mémoire.
#[derive(Default)]
pub struct FakeDns(Mutex<Vec<(String, String)>>);

impl FakeDns {
    pub fn records(&self) -> Vec<(String, String)> {
        self.0.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }
}

#[async_trait]
impl DnsProvider for FakeDns {
    async fn put_txt(&self, name: &str, value: &str) -> anyhow::Result<()> {
        let mut records = self.0.lock().unwrap_or_else(|e| e.into_inner());
        let record = (name.to_owned(), value.to_owned());
        if !records.contains(&record) {
            records.push(record);
        }
        Ok(())
    }

    async fn delete_txt(&self, name: &str, value: &str) -> anyhow::Result<()> {
        self.0.lock().unwrap_or_else(|e| e.into_inner()).retain(|(n, v)| !(n == name && v == value));
        Ok(())
    }
}
