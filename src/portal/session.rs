//! Sessions du portail : jeton opaque en cookie, haché en base.

/// Nom du cookie de session (`__Host-` : `Secure`, `Path=/`, sans `Domain`).
pub const COOKIE: &str = "__Host-agendo-session";
