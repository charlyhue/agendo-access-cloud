//! Clé de signature du plan de contrôle : elle signe les jetons de tunnel et push.
//!
//! La graine Ed25519 (32 octets en base64url) est un secret : fichier monté dont le chemin
//! est `AGENDO_CLOUD_SIGNING_KEY_FILE`, créé par `agendo-access-cloud keygen`. Son `kid` est
//! `AGENDO_CLOUD_SIGNING_KID`. Rotation : nouvelle clé publiée aux relais d'abord, puis
//! l'ancienne reste listée dans `AGENDO_CLOUD_PUBLISHED_KEYS` le temps que ses jetons expirent.

use std::{io::Write, path::Path};

use agendo_access_protocol::{
    SigningKey, b64,
    api::TokensResponse,
    keys::{KeyError, TrustedKey, TrustedKeys, encode_public_key},
    token::{PushClaims, TOKEN_LIFETIME_SECS, TunnelClaims},
    unb64,
};

use crate::config::{Config, ConfigError, Vars, read_secret_file};

pub struct Signer {
    kid: String,
    key: SigningKey,
    /// Clés publiques encore publiées en plus de la courante (rotation).
    published: Vec<TrustedKey>,
}

impl Signer {
    /// Signataire depuis une graine Ed25519 ; vérifie que `kid` et les clés publiées forment
    /// une liste valide (kid uniques, clés bien encodées).
    pub fn from_seed(seed: [u8; 32], kid: &str, published: Vec<TrustedKey>) -> Result<Self, KeyError> {
        let key = SigningKey::from_bytes(&seed);
        let current = TrustedKey { kid: kid.to_owned(), key: encode_public_key(&key.verifying_key()) };
        let mut all = vec![current];
        all.extend(published.iter().cloned());
        TrustedKeys::new(all)?;
        Ok(Self { kid: kid.to_owned(), key, published })
    }

    pub fn from_env(vars: &dyn Vars) -> Result<Self, ConfigError> {
        const FILE: &str = "AGENDO_CLOUD_SIGNING_KEY_FILE";
        let invalid = |name: &str, reason: String| ConfigError::Invalid { name: name.into(), reason };
        let seed: [u8; 32] = unb64(&read_secret_file(vars, FILE)?)
            .ok()
            .and_then(|s| s.try_into().ok())
            .ok_or_else(|| invalid(FILE, "le fichier doit contenir 32 octets en base64url (agendo-access-cloud keygen)".into()))?;
        let kid = vars.required("AGENDO_CLOUD_SIGNING_KID")?;
        let published = match vars.var("AGENDO_CLOUD_PUBLISHED_KEYS") {
            Some(list) if !list.trim().is_empty() => TrustedKeys::parse_list(&list)
                .map_err(|e| invalid("AGENDO_CLOUD_PUBLISHED_KEYS", e.to_string()))?
                .to_vec(),
            _ => Vec::new(),
        };
        Self::from_seed(seed, &kid, published).map_err(|e| invalid("AGENDO_CLOUD_SIGNING_KID", e.to_string()))
    }

    pub fn kid(&self) -> &str {
        &self.kid
    }

    /// Clés de confiance publiées : la courante d'abord, puis celles de la rotation.
    pub fn trusted(&self) -> Vec<TrustedKey> {
        let current = TrustedKey { kid: self.kid.clone(), key: encode_public_key(&self.key.verifying_key()) };
        std::iter::once(current).chain(self.published.iter().cloned()).collect()
    }

    /// Jetons de tunnel et push d'une maison, valables 24 h à partir de `now` (secondes Unix).
    pub fn issue(&self, house_id: &str, host: &str, house_key: &str, now: i64, config: &Config) -> TokensResponse {
        let exp = now + TOKEN_LIFETIME_SECS;
        let tunnel = TunnelClaims {
            iss: config.api_url.clone(),
            sub: house_id.to_owned(),
            host: host.to_owned(),
            house_key: house_key.to_owned(),
            iat: now,
            exp,
        };
        let push = PushClaims {
            iss: config.api_url.clone(),
            sub: house_id.to_owned(),
            house_key: house_key.to_owned(),
            iat: now,
            exp,
            quotas: config.quotas,
        };
        TokensResponse {
            tunnel_token: tunnel.sign(&self.kid, &self.key),
            push_token: push.sign(&self.kid, &self.key),
            expires_at: exp,
            relays: config.relays.clone(),
            push_urls: config.push_urls.clone(),
        }
    }
}

/// Crée une graine de clé de signature dans `path` (mode 0600, jamais d'écrasement) ; rend
/// le texte à afficher, avec la clé publique à donner aux relais. La graine ne s'affiche pas.
pub fn keygen(path: &Path, kid: &str) -> anyhow::Result<String> {
    let seed = crate::crypto::random_bytes::<32>();
    let signer = Signer::from_seed(seed, kid, Vec::new())?;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .map_err(|e| anyhow::anyhow!("création de {} impossible : {e}", path.display()))?;
    writeln!(file, "{}", b64(&seed))?;
    file.sync_all()?;
    let public = &signer.trusted()[0].key;
    Ok(format!(
        "Graine écrite dans {} (mode 0600).\n\
         Clé publique à ajouter aux clés de confiance des relais (RELAY_TRUSTED_KEYS chez agendo-access-relays) :\n{kid}={public}\n\
         Puis : AGENDO_CLOUD_SIGNING_KID={kid}, AGENDO_CLOUD_SIGNING_KEY_FILE=<chemin monté de ce fichier>.\n",
        path.display()
    ))
}
