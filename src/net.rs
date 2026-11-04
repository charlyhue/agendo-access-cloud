//! Adresse IP cliente, pour les limites de débit.

use std::{
    convert::Infallible,
    net::{IpAddr, Ipv6Addr, SocketAddr},
};

use axum::{
    extract::{ConnectInfo, FromRequestParts},
    http::{HeaderMap, request::Parts},
};

use crate::AppState;

/// Clé de débit du client : son IP (dernière entrée de `X-Forwarded-For` derrière Traefik,
/// `AGENDO_CLOUD_TRUST_X_FORWARDED_FOR=true`, sinon l'adresse de la connexion). Une IPv6 est
/// réduite à son /64 : un client en dispose d'ordinaire d'un entier, et chaque adresse serait
/// sinon un compteur neuf.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientIp(pub String);

pub fn rate_key(headers: &HeaderMap, peer: Option<SocketAddr>, trust_forwarded: bool) -> String {
    let forwarded = trust_forwarded
        .then(|| {
            headers
                .get_all("x-forwarded-for")
                .iter()
                .filter_map(|v| v.to_str().ok())
                .flat_map(|v| v.split(','))
                .last()
                .and_then(|ip| ip.trim().parse::<IpAddr>().ok())
        })
        .flatten();
    match forwarded.or(peer.map(|p| p.ip())) {
        Some(IpAddr::V6(ip)) => match ip.to_ipv4_mapped() {
            Some(v4) => v4.to_string(),
            None => {
                let s = ip.segments();
                format!("{}/64", Ipv6Addr::new(s[0], s[1], s[2], s[3], 0, 0, 0, 0))
            }
        },
        Some(ip) => ip.to_string(),
        None => "inconnue".into(),
    }
}

impl FromRequestParts<AppState> for ClientIp {
    type Rejection = Infallible;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Infallible> {
        let peer = parts.extensions.get::<ConnectInfo<SocketAddr>>().map(|c| c.0);
        Ok(Self(rate_key(&parts.headers, peer, state.config.trust_x_forwarded_for)))
    }
}

#[cfg(test)]
mod tests {
    use axum::http::HeaderMap;

    use super::*;

    fn forwarded(value: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", value.parse().unwrap());
        headers
    }

    #[test]
    fn ipv6_is_grouped_by_64() {
        let a = rate_key(&forwarded("2001:db8:1:2:aaaa::1"), None, true);
        let b = rate_key(&forwarded("2001:db8:1:2:ffff:1:2:3"), None, true);
        let other = rate_key(&forwarded("2001:db8:1:3::1"), None, true);
        assert_eq!(a, b);
        assert_ne!(a, other);
        assert_eq!(a, "2001:db8:1:2::/64");
    }

    #[test]
    fn ipv4_and_forwarded_rules() {
        let peer = Some("10.0.0.9:443".parse().unwrap());
        // Dernière entrée : celle ajoutée par Traefik, pas celle que le client prétend.
        assert_eq!(rate_key(&forwarded("1.1.1.1, 203.0.113.7"), peer, true), "203.0.113.7");
        assert_eq!(rate_key(&forwarded("203.0.113.7"), peer, false), "10.0.0.9");
        assert_eq!(rate_key(&HeaderMap::new(), None, false), "inconnue");
    }
}
