//! `POST /v1/houses/enroll` : rattachement d'une maison par le code affiché dans le portail.

use agendo_access_protocol::{
    api::{EnrollRequest, EnrollResponse, MAX_HOUSE_NAME_LEN, RefusalReason, normalize_enrollment_code},
    keys::decode_public_key,
};
use axum::{
    Json,
    extract::{State, rejection::JsonRejection},
};
use serde_json::json;

use super::ApiError;
use crate::{
    AppState,
    db::{accounts, audit, houses, rate_limit},
    net::ClientIp,
};

/// Nom de maison : blancs extérieurs retirés, 1 à 64 octets, sans caractère de contrôle.
fn house_name(input: &str) -> Option<&str> {
    let name = input.trim();
    (!name.is_empty() && name.len() <= MAX_HOUSE_NAME_LEN && !name.chars().any(char::is_control)).then_some(name)
}

pub async fn enroll(
    State(state): State<AppState>,
    ip: ClientIp,
    request: Result<Json<EnrollRequest>, JsonRejection>,
) -> Result<Json<EnrollResponse>, ApiError> {
    let now = state.clock.now();
    let limit = state.config.limits.ip_per_minute;
    if !rate_limit::hit(&state.db, &format!("enroll:{}", ip.0), chrono::Duration::minutes(1), limit, now).await? {
        return Err(ApiError::new(RefusalReason::RateLimited, "trop de tentatives de rattachement"));
    }
    let Ok(Json(request)) = request else {
        return Err(ApiError::new(RefusalReason::BadRequest, "corps JSON attendu : code, house_key, name"));
    };
    let Some(code) = normalize_enrollment_code(&request.code) else {
        return Err(ApiError::new(RefusalReason::InvalidCode, "code de rattachement mal formé"));
    };
    if decode_public_key(&request.house_key).is_err() {
        return Err(ApiError::new(RefusalReason::BadRequest, "clé publique de la maison invalide"));
    }
    let Some(name) = house_name(&request.name) else {
        return Err(ApiError::new(RefusalReason::BadRequest, "nom de maison vide, trop long (64 octets) ou non imprimable"));
    };

    let mut tx = state.db.begin().await?;
    let Some((code_id, account_id)) = houses::consume_enrollment_code(&mut tx, &code, now).await? else {
        return Err(ApiError::new(RefusalReason::InvalidCode, "code inconnu, expiré ou déjà utilisé"));
    };
    let account = accounts::by_id(&mut *tx, account_id).await?;
    if !account.is_some_and(|a| a.subscription_active) {
        return Err(ApiError::new(RefusalReason::SubscriptionInactive, "l'abonnement du compte n'est pas actif"));
    }
    let house = match houses::insert(&mut tx, account_id, &state.config.zone, name, &request.house_key, now).await {
        Ok(house) => house,
        Err(houses::InsertError::KeyTaken) => {
            return Err(ApiError::new(RefusalReason::BadRequest, "cette clé de maison est déjà rattachée"));
        }
        Err(houses::InsertError::Db(e)) => return Err(e.into()),
    };
    sqlx::query("UPDATE enrollment_codes SET house_id = $2 WHERE id = $1")
        .bind(code_id)
        .bind(house.id)
        .execute(&mut *tx)
        .await?;
    audit::record(&mut *tx, now, "house_enrolled", Some(account_id), Some(house.id), json!({ "host": house.host })).await?;
    tx.commit().await?;
    tracing::info!(compte = %account_id, maison = %house.id, hote = %house.host, "maison rattachée");

    Ok(Json(EnrollResponse {
        house_id: house.id.to_string(),
        host: house.host,
        relays: state.config.relays.clone(),
        push_urls: state.config.push_urls.clone(),
        trusted_keys: state.signer.trusted(),
    }))
}
