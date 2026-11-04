mod common;

use agendo_access_cloud::db::{audit, rate_limit};
use chrono::Duration;
use sqlx::PgPool;

#[sqlx::test]
async fn limit_then_refuse_then_new_window(pool: PgPool) {
    let now = common::start();
    let window = Duration::minutes(1);
    for i in 0..3 {
        assert!(rate_limit::hit(&pool, "ip:1.2.3.4", window, 3, now).await.unwrap(), "passage {i}");
    }
    assert!(!rate_limit::hit(&pool, "ip:1.2.3.4", window, 3, now + Duration::seconds(59)).await.unwrap());
    // Une autre clé a son propre compteur.
    assert!(rate_limit::hit(&pool, "ip:5.6.7.8", window, 3, now).await.unwrap());
    // Fenêtre suivante : de nouveau permis.
    assert!(rate_limit::hit(&pool, "ip:1.2.3.4", window, 3, now + window).await.unwrap());
}

#[sqlx::test]
async fn audit_records_event(pool: PgPool) {
    audit::record(&pool, common::start(), "essai", None, None, serde_json::json!({"cle": "valeur"})).await.unwrap();
    let (event, detail): (String, serde_json::Value) =
        sqlx::query_as("SELECT event, detail FROM audit").fetch_one(&pool).await.unwrap();
    assert_eq!(event, "essai");
    assert_eq!(detail["cle"], "valeur");
}
