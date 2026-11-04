//! Client HTTP sortant (Resend, Cloudflare) : rustls avec ring, délais bornés.

use std::time::Duration;

pub fn client() -> reqwest::Client {
    // Fournisseur crypto du processus ; déjà installé, ce n'est pas une erreur.
    let _ = rustls::crypto::ring::default_provider().install_default();
    reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .connect_timeout(Duration::from_secs(5))
        .build()
        .expect("client HTTP : configuration TLS invalide")
}
