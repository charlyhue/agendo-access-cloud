//! Fournisseur DNS des défis ACME DNS-01 : poser et retirer un TXT `_acme-challenge.<hôte>`.
//!
//! `FakeDns` pour les tests et le développement ; `CloudflareDns` en production *(choix de
//! conception de la spec, à remplacer si la personne choisit un autre fournisseur)*.

use std::sync::Mutex;

use async_trait::async_trait;

/// Valeurs TXT gardées par nom : un défi DNS-01 n'en demande jamais plus de deux à la fois.
/// Au-delà, les plus anciennes sont retirées, pour qu'une maison (ou sa clé volée) ne puisse
/// pas remplir la zone, et qu'un défi abandonné ne reste pas.
pub const MAX_TXT_VALUES: usize = 2;

#[async_trait]
pub trait DnsProvider: Send + Sync {
    /// Pose un enregistrement TXT `name` de valeur `value` (nom complet, sans point final), en
    /// ne gardant que les [`MAX_TXT_VALUES`] plus récentes valeurs de ce nom.
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
        if records.contains(&record) {
            return Ok(());
        }
        // Les plus anciennes valeurs du nom au-delà de la borne partent.
        let same: Vec<usize> = records.iter().enumerate().filter(|(_, (n, _))| n == name).map(|(i, _)| i).collect();
        let excess = (same.len() + 1).saturating_sub(MAX_TXT_VALUES);
        for i in same.into_iter().take(excess).rev() {
            records.remove(i);
        }
        records.push(record);
        Ok(())
    }

    async fn delete_txt(&self, name: &str, value: &str) -> anyhow::Result<()> {
        self.0.lock().unwrap_or_else(|e| e.into_inner()).retain(|(n, v)| !(n == name && v == value));
        Ok(())
    }
}

/// Cloudflare DNS (API v4) : enregistrements TXT de la zone `zone_id`, jeton d'API limité à
/// « DNS : modifier » sur cette zone. Une erreur ne cite que le statut et les codes d'erreur.
pub struct CloudflareDns {
    client: reqwest::Client,
    records_url: String,
    token: String,
}

#[derive(serde::Deserialize)]
struct CfResponse {
    #[serde(default)]
    success: bool,
    #[serde(default)]
    errors: Vec<CfError>,
    #[serde(default)]
    result: serde_json::Value,
}

#[derive(serde::Deserialize)]
struct CfError {
    code: i64,
}

#[derive(serde::Deserialize)]
struct CfRecord {
    id: String,
    content: String,
    #[serde(default)]
    created_on: String,
}

/// Code Cloudflare « un enregistrement identique existe déjà ».
const CF_IDENTICAL_RECORD: i64 = 81058;

impl CloudflareDns {
    pub fn new(api_url: &str, token: String, zone_id: String) -> Self {
        let records_url = format!("{}/zones/{zone_id}/dns_records", api_url.trim_end_matches('/'));
        Self { client: crate::http::client(), records_url, token }
    }

    /// TXT du nom, du plus ancien au plus récent (dates RFC 3339 : l'ordre du texte suffit).
    async fn list(&self, name: &str) -> anyhow::Result<Vec<CfRecord>> {
        let query = [("type", "TXT"), ("name", name), ("per_page", "100")];
        let listed = self.call(self.client.get(&self.records_url).query(&query)).await?;
        let mut records: Vec<CfRecord> = serde_json::from_value(listed.result).unwrap_or_default();
        records.sort_by(|a, b| a.created_on.cmp(&b.created_on));
        Ok(records)
    }

    async fn delete(&self, record: &CfRecord) -> anyhow::Result<()> {
        self.call(self.client.delete(format!("{}/{}", self.records_url, record.id))).await.map(drop)
    }

    async fn call(&self, request: reqwest::RequestBuilder) -> anyhow::Result<CfResponse> {
        let response = request
            .bearer_auth(&self.token)
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("Cloudflare injoignable : {}", e.without_url()))?;
        let status = response.status();
        let body: CfResponse = response.json().await.unwrap_or(CfResponse { success: false, errors: Vec::new(), result: Default::default() });
        if !status.is_success() || !body.success {
            let codes: Vec<String> = body.errors.iter().map(|e| e.code.to_string()).collect();
            anyhow::bail!("Cloudflare refuse la requête (statut {}, codes {})", status.as_u16(), codes.join(","));
        }
        Ok(body)
    }
}

#[async_trait]
impl DnsProvider for CloudflareDns {
    async fn put_txt(&self, name: &str, value: &str) -> anyhow::Result<()> {
        let existing = self.list(name).await?;
        if existing.iter().any(|r| r.content.trim_matches('"') == value) {
            return Ok(());
        }
        let excess = (existing.len() + 1).saturating_sub(MAX_TXT_VALUES);
        for record in existing.iter().take(excess) {
            self.delete(record).await?;
        }
        let body = serde_json::json!({ "type": "TXT", "name": name, "content": value, "ttl": 60 });
        match self.call(self.client.post(&self.records_url).json(&body)).await {
            Ok(_) => Ok(()),
            // Nouvel essai de la maison : l'enregistrement est déjà là.
            Err(e) if e.to_string().contains(&CF_IDENTICAL_RECORD.to_string()) => Ok(()),
            Err(e) => Err(e),
        }
    }

    async fn delete_txt(&self, name: &str, value: &str) -> anyhow::Result<()> {
        for record in self.list(name).await?.iter().filter(|r| r.content.trim_matches('"') == value) {
            self.delete(record).await?;
        }
        Ok(())
    }
}

/// Fournisseur selon `AGENDO_CLOUD_DNS` : `cloudflare` (production) ou `fake` (développement,
/// rien n'est publié).
pub fn from_env(vars: &dyn crate::config::Vars) -> Result<std::sync::Arc<dyn DnsProvider>, crate::config::ConfigError> {
    use crate::config::{ConfigError, read_secret_file};
    match vars.required("AGENDO_CLOUD_DNS")?.as_str() {
        "cloudflare" => {
            let api_url = vars
                .var("AGENDO_CLOUD_CLOUDFLARE_API_URL")
                .filter(|v| !v.trim().is_empty())
                .unwrap_or_else(|| "https://api.cloudflare.com/client/v4".into());
            let token = read_secret_file(vars, "AGENDO_CLOUD_CLOUDFLARE_TOKEN_FILE")?;
            let zone = vars.required("AGENDO_CLOUD_CLOUDFLARE_ZONE_ID")?;
            Ok(std::sync::Arc::new(CloudflareDns::new(api_url.trim(), token, zone)))
        }
        "fake" => {
            tracing::warn!("fournisseur DNS factice : aucun défi ACME ne sera publié");
            Ok(std::sync::Arc::new(FakeDns::default()))
        }
        other => Err(ConfigError::Invalid { name: "AGENDO_CLOUD_DNS".into(), reason: format!("{other:?} : cloudflare ou fake attendu") }),
    }
}
