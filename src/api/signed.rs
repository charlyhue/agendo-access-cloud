//! Requêtes signées par la maison : `Agendo-House` (identifiant reçu au rattachement) et
//! `Agendo-Signature` (protocole, `signature::verify_request`), puis jetons et ACME.
//!
//! `Agendo-House` n'est pas signé : il désigne la clé contre laquelle vérifier, et un
//! identifiant faux fait simplement échouer la vérification.

use agendo_access_protocol::{
    api::{AcmeRequest, RefusalReason, TokensResponse},
    keys::decode_public_key,
    signature::{SIGNATURE_HEADER, SignatureError, verify_request},
};
use axum::{
    Json,
    body::Bytes,
    extract::{FromRequest, FromRequestParts, Request, State},
    http::StatusCode,
};
use uuid::Uuid;

use super::ApiError;
use crate::{
    AppState,
    db::{accounts, houses::{self, House}, rate_limit},
    net::ClientIp,
};

/// En-tête qui désigne la maison qui signe.
pub const HOUSE_HEADER: &str = "agendo-house";
/// Taille maximale du corps d'une requête signée.
const MAX_BODY: usize = 16 * 1024;

/// Maison authentifiée par sa signature, avec le corps (déjà lu) de sa requête.
pub struct SignedHouse {
    pub house: House,
    pub body: Bytes,
}

fn bad_signature(detail: &str) -> ApiError {
    ApiError::new(RefusalReason::BadSignature, detail)
}

impl FromRequest<AppState> for SignedHouse {
    type Rejection = ApiError;

    async fn from_request(request: Request, state: &AppState) -> Result<Self, ApiError> {
        let (mut parts, body) = request.into_parts();
        let now = state.clock.now();
        let ip = match ClientIp::from_request_parts(&mut parts, state).await {
            Ok(ip) => ip,
            Err(never) => match never {},
        };
        let window = chrono::Duration::minutes(1);
        if !rate_limit::hit(&state.db, &format!("maison-ip:{}", ip.0), window, state.config.limits.ip_per_minute, now).await? {
            return Err(ApiError::new(RefusalReason::RateLimited, "trop de requêtes depuis cette adresse"));
        }
        let header = |name: &str| parts.headers.get(name).and_then(|v| v.to_str().ok()).map(str::to_owned);
        let Some(house_id) = header(HOUSE_HEADER).and_then(|v| Uuid::parse_str(v.trim()).ok()) else {
            return Err(bad_signature("en-tête Agendo-House absent ou invalide"));
        };
        let Some(signature) = header(SIGNATURE_HEADER) else {
            return Err(bad_signature("en-tête Agendo-Signature absent"));
        };
        let body = axum::body::to_bytes(body, MAX_BODY)
            .await
            .map_err(|_| ApiError::new(RefusalReason::BadRequest, "corps trop volumineux"))?;
        let Some(house) = houses::by_id(&state.db, house_id).await? else {
            return Err(bad_signature("maison inconnue"));
        };
        let key = decode_public_key(&house.public_key).map_err(|e| anyhow::anyhow!("clé de maison en base invalide : {e}"))?;
        let path = parts.uri.path_and_query().map_or(parts.uri.path(), |p| p.as_str());
        verify_request(&signature, parts.method.as_str(), path, &body, now.timestamp(), &key).map_err(|e| match e {
            SignatureError::Stale => bad_signature("horodatage hors de la fenêtre de 60 s : vérifiez l'horloge de la maison"),
            SignatureError::Malformed => bad_signature("en-tête Agendo-Signature mal formé"),
            SignatureError::Invalid => bad_signature("signature invalide"),
        })?;
        let limit = state.config.limits.house_per_minute;
        if !rate_limit::hit(&state.db, &format!("maison:{}", house.id), window, limit, now).await? {
            return Err(ApiError::new(RefusalReason::RateLimited, "trop de requêtes pour cette maison"));
        }
        Ok(Self { house, body })
    }
}

/// La maison peut-elle encore recevoir le service ? Révoquée (ou détachée de son compte
/// supprimé) : `revoked` ; compte sans abonnement actif : `subscription_inactive`.
async fn check_service(state: &AppState, house: &House) -> Result<(), ApiError> {
    let revoked = || ApiError::new(RefusalReason::Revoked, "maison révoquée : la rattacher de nouveau");
    let Some(account) = house.account_id.filter(|_| house.revoked_at.is_none()) else { return Err(revoked()) };
    let Some(account) = accounts::by_id(&state.db, account).await? else { return Err(revoked()) };
    if !account.subscription_active {
        return Err(ApiError::new(RefusalReason::SubscriptionInactive, "l'abonnement du compte n'est pas actif"));
    }
    Ok(())
}

/// `POST /v1/houses/tokens` : jetons de tunnel et push, valables 24 h.
pub async fn tokens(State(state): State<AppState>, signed: SignedHouse) -> Result<Json<TokensResponse>, ApiError> {
    let house = signed.house;
    check_service(&state, &house).await?;
    let now = state.clock.now();
    let tokens = state.signer.issue(&house.id.to_string(), &house.host, &house.public_key, now.timestamp(), &state.config);
    houses::tokens_issued(&state.db, house.id, now).await?;
    tracing::info!(maison = %house.id, "jetons délivrés");
    Ok(Json(tokens))
}

/// Valeur d'un défi DNS-01 : base64url (le condensé ACME en fait 43 caractères), 255 au plus.
fn acme_value(body: &[u8]) -> Result<String, ApiError> {
    let bad = || ApiError::new(RefusalReason::BadRequest, "corps attendu : {\"value\": <base64url, 255 caractères au plus>}");
    let request: AcmeRequest = serde_json::from_slice(body).map_err(|_| bad())?;
    let ok = !request.value.is_empty()
        && request.value.len() <= 255
        && request.value.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
    if ok { Ok(request.value) } else { Err(bad()) }
}

async fn acme(state: AppState, signed: SignedHouse, put: bool) -> Result<StatusCode, ApiError> {
    let house = signed.house;
    check_service(&state, &house).await?;
    let value = acme_value(&signed.body)?;
    let name = format!("_acme-challenge.{}", house.host);
    let result = if put { state.dns.put_txt(&name, &value).await } else { state.dns.delete_txt(&name, &value).await };
    result.map_err(|e| {
        tracing::error!(maison = %house.id, erreur = %format!("{e:#}"), "fournisseur DNS en échec");
        ApiError::new(RefusalReason::Unknown, "fournisseur DNS indisponible : réessayer plus tard")
    })?;
    tracing::info!(maison = %house.id, pose = put, "défi ACME DNS-01");
    Ok(StatusCode::NO_CONTENT)
}

/// `POST /v1/houses/acme` : pose le TXT `_acme-challenge.<hôte>` de la maison qui signe.
pub async fn acme_put(State(state): State<AppState>, signed: SignedHouse) -> Result<StatusCode, ApiError> {
    acme(state, signed, true).await
}

/// `DELETE /v1/houses/acme` : retire ce TXT.
pub async fn acme_delete(State(state): State<AppState>, signed: SignedHouse) -> Result<StatusCode, ApiError> {
    acme(state, signed, false).await
}
