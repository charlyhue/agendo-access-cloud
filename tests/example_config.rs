//! La configuration d'exemple (`deploy/exemple.env`) reste valide : elle se charge avec le vrai
//! lecteur de configuration, et chaque variable lue par le service y figure.
use std::collections::HashMap;

use agendo_access_cloud::config::Config;

fn example() -> HashMap<String, String> {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/deploy/exemple.env");
    let text = std::fs::read_to_string(path).expect("deploy/exemple.env");
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| {
            let (k, v) = l.split_once('=').unwrap_or_else(|| panic!("ligne sans = : {l}"));
            (k.trim().to_owned(), v.trim().to_owned())
        })
        .collect()
}

#[test]
fn example_config_loads() {
    let vars = example();
    let config = Config::from_vars(&|name: &str| vars.get(name).cloned()).expect("configuration d'exemple valide");
    // Le portail sert de RP ID WebAuthn : son hôte, sans port.
    assert_eq!(config.portal_link("/"), format!("https://{}/", config.rp_id()));
    assert!(!config.relays.is_empty() && !config.push_urls.is_empty());
    assert!(config.trust_x_forwarded_for, "derrière Traefik");
}

#[test]
fn example_lists_every_variable_read() {
    let vars = example();
    let sources: String = ["config.rs", "mail.rs", "dns.rs", "signing.rs"]
        .iter()
        .map(|f| std::fs::read_to_string(format!("{}/src/{f}", env!("CARGO_MANIFEST_DIR"))).unwrap())
        .collect();
    let read: std::collections::BTreeSet<&str> = sources
        .split('"')
        .filter(|s| s.starts_with("AGENDO_CLOUD_") && s.bytes().all(|b| b.is_ascii_uppercase() || b == b'_'))
        .collect();
    // Variables propres au développement ou facultatives à valeur par défaut.
    let optional = ["AGENDO_CLOUD_OUTBOX_DIR", "AGENDO_CLOUD_RESEND_API_URL", "AGENDO_CLOUD_CLOUDFLARE_API_URL"];
    for name in read {
        assert!(vars.contains_key(name) || optional.contains(&name), "{name} absente de deploy/exemple.env");
    }
}

/// Les domaines de l'exemple ne sont écrits nulle part dans le code (règle « aucun domaine en
/// dur ») : lus dans l'exemple, cherchés dans les sources.
#[test]
fn example_domains_are_not_in_code() {
    let vars = example();
    let config = Config::from_vars(&|name: &str| vars.get(name).cloned()).unwrap();
    let host = |url: &str| url::Url::parse(url).unwrap().host_str().unwrap().to_owned();
    let mut domains = vec![host(&config.api_url), config.rp_id().to_owned(), config.zone.clone()];
    domains.extend(config.relays.iter().map(|r| r.trim_start_matches("tls://").split(':').next().unwrap().to_owned()));
    domains.extend(config.push_urls.iter().map(|u| host(u)));
    // Domaine enregistré commun (les deux derniers labels de la zone).
    let labels: Vec<&str> = config.zone.rsplitn(3, '.').collect();
    domains.push(format!("{}.{}", labels[1], labels[0]));

    fn files(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
        for entry in std::fs::read_dir(dir).unwrap().flatten() {
            let path = entry.path();
            if path.is_dir() { files(&path, out) } else { out.push(path) }
        }
    }
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut all = Vec::new();
    for dir in ["src", "templates", "static", "migrations", "tests"] {
        files(&root.join(dir), &mut all);
    }
    for path in all {
        let text = std::fs::read_to_string(&path).unwrap_or_default();
        for domain in &domains {
            assert!(!text.contains(domain.as_str()), "{domain} écrit dans {}", path.display());
        }
    }
}
