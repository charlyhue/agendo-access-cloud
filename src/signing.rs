//! Clé de signature du plan de contrôle : elle signe les jetons de tunnel et push.

use agendo_access_protocol::{
    SigningKey,
    keys::{KeyError, TrustedKey, TrustedKeys, encode_public_key},
};

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

    pub fn kid(&self) -> &str {
        &self.kid
    }
}
