//! Adresse IP cliente, pour les limites de débit.

use std::{convert::Infallible, net::{IpAddr, SocketAddr}};

use axum::{
    extract::{ConnectInfo, FromRequestParts},
    http::request::Parts,
};

use crate::AppState;

/// IP du client : dernière entrée de `X-Forwarded-For` derrière Traefik
/// (`AGENDO_CLOUD_TRUST_X_FORWARDED_FOR=true`), sinon l'adresse de la connexion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientIp(pub String);

impl FromRequestParts<AppState> for ClientIp {
    type Rejection = Infallible;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Infallible> {
        if state.config.trust_x_forwarded_for {
            let forwarded = parts
                .headers
                .get_all("x-forwarded-for")
                .iter()
                .filter_map(|v| v.to_str().ok())
                .flat_map(|v| v.split(','))
                .last()
                .and_then(|ip| ip.trim().parse::<IpAddr>().ok());
            if let Some(ip) = forwarded {
                return Ok(Self(ip.to_string()));
            }
        }
        let peer = parts.extensions.get::<ConnectInfo<SocketAddr>>().map(|c| c.0.ip().to_string());
        Ok(Self(peer.unwrap_or_else(|| "inconnue".into())))
    }
}
