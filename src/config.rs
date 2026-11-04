//! Configuration, entièrement par variables d'environnement (`docs/deploy.md`).
//!
//! Aucun domaine ni seuil anti-abus n'est écrit dans le code : tout ce qui est propre au
//! déploiement est obligatoire ici. Les secrets ne passent jamais par une variable : la
//! variable `…_FILE` donne le chemin d'un fichier monté ([`read_secret_file`]).

use std::net::SocketAddr;

use agendo_access_protocol::{api::RelayAddr, token::Quotas};
use url::Url;

/// Erreur de configuration : elle nomme la variable, jamais la valeur d'un secret.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConfigError {
    #[error("variable d'environnement {0} manquante")]
    Missing(String),
    #[error("variable d'environnement {name} invalide : {reason}")]
    Invalid { name: String, reason: String },
}

fn invalid(name: &str, reason: impl Into<String>) -> ConfigError {
    ConfigError::Invalid { name: name.to_owned(), reason: reason.into() }
}

/// Seuils anti-abus.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Cérémonies du portail (connexion, codes, passkeys) et rattachements, par IP et par minute.
    pub ip_per_minute: u32,
    /// Codes de connexion envoyés par e-mail, par compte et par heure.
    pub email_codes_per_hour: u32,
    /// Requêtes signées d'une maison, par minute.
    pub house_per_minute: u32,
}

#[derive(Debug, Clone)]
pub struct Config {
    pub listen: SocketAddr,
    /// URL de l'API des maisons (`https://api.DOMAINE`), `iss` des jetons.
    pub api_url: String,
    portal: Url,
    /// `ZONE_MAISONS`, en minuscules, sans point final.
    pub zone: String,
    /// Relais SNI annoncés, `tls://hôte:port`.
    pub relays: Vec<String>,
    /// Relais push, URL de base `https://…`.
    pub push_urls: Vec<String>,
    /// Derrière Traefik : l'IP cliente est la dernière entrée de `X-Forwarded-For`.
    pub trust_x_forwarded_for: bool,
    pub limits: Limits,
    /// Quotas portés par les jetons push.
    pub quotas: Quotas,
}

/// Lecture d'une variable par son nom (l'environnement, ou une table dans les tests).
pub trait Vars {
    fn var(&self, name: &str) -> Option<String>;

    fn required(&self, name: &str) -> Result<String, ConfigError> {
        self.var(name)
            .map(|v| v.trim().to_owned())
            .filter(|v| !v.is_empty())
            .ok_or_else(|| ConfigError::Missing(name.to_owned()))
    }

    fn number(&self, name: &str) -> Result<u32, ConfigError> {
        self.required(name)?.parse().map_err(|_| invalid(name, "entier positif attendu"))
    }
}

/// Variables d'environnement du processus.
pub struct Env;

impl Vars for Env {
    fn var(&self, name: &str) -> Option<String> {
        std::env::var(name).ok()
    }
}

impl<F: Fn(&str) -> Option<String>> Vars for F {
    fn var(&self, name: &str) -> Option<String> {
        self(name)
    }
}

/// Contenu d'un secret monté : la variable `name` donne le chemin du fichier. Blancs autour
/// retirés ; un fichier vide est une erreur. Le message d'erreur ne cite que le chemin.
pub fn read_secret_file(vars: &dyn Vars, name: &str) -> Result<String, ConfigError> {
    let path = vars.required(name)?;
    let content = std::fs::read_to_string(&path)
        .map_err(|e| invalid(name, format!("fichier {path} illisible : {e}")))?;
    let content = content.trim();
    if content.is_empty() {
        return Err(invalid(name, format!("fichier {path} vide")));
    }
    Ok(content.to_owned())
}

/// URL de la base (`AGENDO_CLOUD_DATABASE_URL_FILE`, elle contient le mot de passe).
pub fn database_url(vars: &dyn Vars) -> Result<String, ConfigError> {
    read_secret_file(vars, "AGENDO_CLOUD_DATABASE_URL_FILE")
}

/// URL web : `https`, ou `http` sur la boucle locale (développement).
fn web_url(name: &str, text: &str) -> Result<Url, ConfigError> {
    let url = Url::parse(text).map_err(|e| invalid(name, e.to_string()))?;
    let host = url.host_str().ok_or_else(|| invalid(name, "hôte manquant"))?;
    let local = host == "localhost" || host.ends_with(".localhost") || host == "127.0.0.1";
    match url.scheme() {
        "https" => {}
        "http" if local => {}
        _ => return Err(invalid(name, "https:// attendu")),
    }
    if !url.username().is_empty() || url.password().is_some() || url.query().is_some() || url.fragment().is_some() {
        return Err(invalid(name, "ni identifiants, ni requête, ni fragment"));
    }
    Ok(url)
}

/// URL de base sans `/` final.
fn base_url(name: &str, text: &str) -> Result<String, ConfigError> {
    Ok(web_url(name, text)?.as_str().trim_end_matches('/').to_owned())
}

fn list(vars: &dyn Vars, name: &str) -> Result<Vec<String>, ConfigError> {
    let items: Vec<String> =
        vars.required(name)?.split(',').map(str::trim).filter(|s| !s.is_empty()).map(str::to_owned).collect();
    if items.is_empty() {
        return Err(ConfigError::Missing(name.to_owned()));
    }
    Ok(items)
}

impl Config {
    pub fn from_env() -> Result<Self, ConfigError> {
        Self::from_vars(&Env)
    }

    pub fn from_vars(vars: &dyn Vars) -> Result<Self, ConfigError> {
        let listen = match vars.var("AGENDO_CLOUD_LISTEN").filter(|v| !v.trim().is_empty()) {
            Some(v) => v.trim().parse().map_err(|_| invalid("AGENDO_CLOUD_LISTEN", "adresse:port attendu"))?,
            None => SocketAddr::from(([0, 0, 0, 0], 8080)),
        };
        let api_url = base_url("AGENDO_CLOUD_API_URL", &vars.required("AGENDO_CLOUD_API_URL")?)?;
        let portal = web_url("AGENDO_CLOUD_PORTAL_URL", &vars.required("AGENDO_CLOUD_PORTAL_URL")?)?;
        if portal.path() != "/" {
            return Err(invalid("AGENDO_CLOUD_PORTAL_URL", "origine seule attendue, sans chemin"));
        }
        let zone = vars.required("AGENDO_CLOUD_ZONE")?.trim_end_matches('.').to_ascii_lowercase();
        let zone_ok = zone.contains('.')
            && zone.split('.').all(|l| !l.is_empty() && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'));
        if !zone_ok {
            return Err(invalid("AGENDO_CLOUD_ZONE", "nom de domaine attendu"));
        }
        let relays = list(vars, "AGENDO_CLOUD_RELAYS")?
            .iter()
            .map(|r| {
                RelayAddr::parse(r)
                    .map(|a| a.to_string())
                    .ok_or_else(|| invalid("AGENDO_CLOUD_RELAYS", format!("{r:?} n'est pas tls://hôte[:port]")))
            })
            .collect::<Result<_, _>>()?;
        let push_urls = list(vars, "AGENDO_CLOUD_PUSH_URLS")?
            .iter()
            .map(|u| base_url("AGENDO_CLOUD_PUSH_URLS", u))
            .collect::<Result<_, _>>()?;
        // Obligatoire : derrière Traefik, `false` ferait partager à tous les clients l'IP du
        // proxy, donc les mêmes limites de débit.
        let trust_x_forwarded_for = match vars.required("AGENDO_CLOUD_TRUST_X_FORWARDED_FOR")?.as_str() {
            "false" => false,
            "true" => true,
            _ => return Err(invalid("AGENDO_CLOUD_TRUST_X_FORWARDED_FOR", "true ou false attendu")),
        };
        Ok(Self {
            listen,
            api_url,
            portal,
            zone,
            relays,
            push_urls,
            trust_x_forwarded_for,
            limits: Limits {
                ip_per_minute: vars.number("AGENDO_CLOUD_LIMIT_IP_PER_MINUTE")?,
                email_codes_per_hour: vars.number("AGENDO_CLOUD_LIMIT_EMAIL_CODES_PER_HOUR")?,
                house_per_minute: vars.number("AGENDO_CLOUD_LIMIT_HOUSE_PER_MINUTE")?,
            },
            quotas: Quotas {
                per_hour: vars.number("AGENDO_CLOUD_PUSH_PER_HOUR")?,
                critical_per_day: vars.number("AGENDO_CLOUD_PUSH_CRITICAL_PER_DAY")?,
            },
        })
    }

    /// Configuration d'exemple des tests (domaines `exemple.fr`, jamais servis).
    pub fn for_tests() -> Self {
        let vars = |name: &str| {
            Some(
                match name {
                    "AGENDO_CLOUD_API_URL" => "https://api.exemple.fr",
                    "AGENDO_CLOUD_PORTAL_URL" => "https://compte.exemple.fr",
                    "AGENDO_CLOUD_ZONE" => "maisons.exemple.fr",
                    "AGENDO_CLOUD_RELAYS" => "tls://relais.exemple.fr",
                    "AGENDO_CLOUD_PUSH_URLS" => "https://push.exemple.fr",
                    "AGENDO_CLOUD_LIMIT_IP_PER_MINUTE" => "30",
                    "AGENDO_CLOUD_LIMIT_EMAIL_CODES_PER_HOUR" => "5",
                    "AGENDO_CLOUD_LIMIT_HOUSE_PER_MINUTE" => "20",
                    "AGENDO_CLOUD_PUSH_PER_HOUR" => "60",
                    "AGENDO_CLOUD_PUSH_CRITICAL_PER_DAY" => "10",
                    "AGENDO_CLOUD_TRUST_X_FORWARDED_FOR" => "false",
                    _ => return None,
                }
                .to_owned(),
            )
        };
        Self::from_vars(&vars).expect("configuration de test valide")
    }

    /// Origine du portail (`https://compte.DOMAINE`), attendue par WebAuthn et sur les POST.
    pub fn portal_origin(&self) -> String {
        self.portal.origin().ascii_serialization()
    }

    /// RP ID WebAuthn : l'hôte du portail.
    pub fn rp_id(&self) -> &str {
        self.portal.host_str().unwrap_or_default()
    }

    /// Lien absolu vers une page du portail (`path` commence par `/`).
    pub fn portal_link(&self, path: &str) -> String {
        format!("{}{path}", self.portal_origin())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    fn base() -> HashMap<&'static str, &'static str> {
        HashMap::from([
            ("AGENDO_CLOUD_API_URL", "https://api.exemple.fr/"),
            ("AGENDO_CLOUD_PORTAL_URL", "https://compte.exemple.fr"),
            ("AGENDO_CLOUD_ZONE", "Maisons.Exemple.fr."),
            ("AGENDO_CLOUD_RELAYS", "tls://relais.exemple.fr, tls://relais2.exemple.fr:9443"),
            ("AGENDO_CLOUD_PUSH_URLS", "https://push.exemple.fr"),
            ("AGENDO_CLOUD_LIMIT_IP_PER_MINUTE", "30"),
            ("AGENDO_CLOUD_LIMIT_EMAIL_CODES_PER_HOUR", "5"),
            ("AGENDO_CLOUD_LIMIT_HOUSE_PER_MINUTE", "20"),
            ("AGENDO_CLOUD_PUSH_PER_HOUR", "60"),
            ("AGENDO_CLOUD_PUSH_CRITICAL_PER_DAY", "10"),
            ("AGENDO_CLOUD_TRUST_X_FORWARDED_FOR", "false"),
        ])
    }

    fn load(map: &HashMap<&'static str, &'static str>) -> Result<Config, ConfigError> {
        Config::from_vars(&|name: &str| map.get(name).map(|v| v.to_string()))
    }

    #[test]
    fn full_config_is_normalized() {
        let config = load(&base()).unwrap();
        assert_eq!(config.api_url, "https://api.exemple.fr");
        assert_eq!(config.portal_origin(), "https://compte.exemple.fr");
        assert_eq!(config.rp_id(), "compte.exemple.fr");
        assert_eq!(config.zone, "maisons.exemple.fr");
        assert_eq!(config.relays, ["tls://relais.exemple.fr:443", "tls://relais2.exemple.fr:9443"]);
        assert_eq!(config.listen.to_string(), "0.0.0.0:8080");
        assert!(!config.trust_x_forwarded_for);
        assert_eq!(config.quotas, Quotas { per_hour: 60, critical_per_day: 10 });
        assert_eq!(config.portal_link("/connexion"), "https://compte.exemple.fr/connexion");
    }

    #[test]
    fn missing_variable_is_named() {
        for name in [
            "AGENDO_CLOUD_ZONE",
            "AGENDO_CLOUD_LIMIT_HOUSE_PER_MINUTE",
            "AGENDO_CLOUD_PUSH_PER_HOUR",
            // Obligatoire : par défaut, derrière Traefik, tous les clients partageraient une IP.
            "AGENDO_CLOUD_TRUST_X_FORWARDED_FOR",
        ] {
            let mut map = base();
            map.remove(name);
            assert_eq!(load(&map).unwrap_err(), ConfigError::Missing(name.into()));
        }
    }

    #[test]
    fn bad_values_are_refused() {
        for (name, value) in [
            ("AGENDO_CLOUD_RELAYS", "https://relais.exemple.fr"),
            ("AGENDO_CLOUD_API_URL", "http://api.exemple.fr"),
            ("AGENDO_CLOUD_PORTAL_URL", "https://compte.exemple.fr/portail"),
            ("AGENDO_CLOUD_ZONE", "maisons"),
            ("AGENDO_CLOUD_LIMIT_IP_PER_MINUTE", "beaucoup"),
            ("AGENDO_CLOUD_TRUST_X_FORWARDED_FOR", "oui"),
        ] {
            let mut map = base();
            map.insert(name, value);
            assert!(
                matches!(load(&map), Err(ConfigError::Invalid { name: n, .. }) if n == name),
                "{name}={value}"
            );
        }
    }

    #[test]
    fn local_http_is_allowed_for_development() {
        let mut map = base();
        map.insert("AGENDO_CLOUD_PORTAL_URL", "http://localhost:8080");
        let config = load(&map).unwrap();
        assert_eq!(config.portal_origin(), "http://localhost:8080");
        assert_eq!(config.rp_id(), "localhost");
    }

    #[test]
    fn secret_file_is_read_and_trimmed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret");
        std::fs::write(&path, "  valeur\n").unwrap();
        let path = path.to_string_lossy().into_owned();
        let vars = |name: &str| (name == "X_FILE").then(|| path.clone());
        assert_eq!(read_secret_file(&vars, "X_FILE").unwrap(), "valeur");
        std::fs::write(dir.path().join("secret"), "\n").unwrap();
        assert!(matches!(read_secret_file(&vars, "X_FILE"), Err(ConfigError::Invalid { .. })));
        let none = |_: &str| None;
        assert_eq!(read_secret_file(&none, "X_FILE"), Err(ConfigError::Missing("X_FILE".into())));
    }
}
