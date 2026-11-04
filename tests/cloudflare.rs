use std::sync::{Arc, Mutex};

use agendo_access_cloud::dns::{CloudflareDns, DnsProvider};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    routing::{delete, get},
};
use serde_json::{Value, json};

#[derive(Default)]
struct Zone {
    records: Vec<(String, String, String)>,
    next: u32,
    bad_auth: u32,
}

type Shared = Arc<Mutex<Zone>>;

fn authorized(headers: &HeaderMap, zone: &Shared) -> bool {
    let ok = headers.get("authorization").and_then(|v| v.to_str().ok()) == Some("Bearer jeton-dns");
    if !ok {
        zone.lock().unwrap().bad_auth += 1;
    }
    ok
}

async fn fake_cloudflare() -> (String, Shared) {
    let zone: Shared = Arc::default();
    let app = Router::new()
        .route(
            "/zones/z1/dns_records",
            get(|State(zone): State<Shared>, headers: HeaderMap, Query(q): Query<std::collections::HashMap<String, String>>| async move {
                if !authorized(&headers, &zone) {
                    return (StatusCode::FORBIDDEN, Json(json!({"success": false, "errors": [{"code": 10000}]})));
                }
                assert_eq!(q.get("type").map(String::as_str), Some("TXT"));
                let name = q.get("name").cloned().unwrap_or_default();
                let result: Vec<Value> = zone
                    .lock()
                    .unwrap()
                    .records
                    .iter()
                    .filter(|(_, n, _)| *n == name)
                    // Cloudflare rend le contenu TXT entre guillemets.
                    .map(|(id, n, c)| {
                        let created = format!("2026-11-04T12:00:{:02}Z", id[1..].parse::<u32>().unwrap());
                        json!({"id": id, "type": "TXT", "name": n, "content": format!("\"{c}\""), "created_on": created})
                    })
                    // L'API ne promet pas d'ordre : on les rend du plus récent au plus ancien.
                    .rev()
                    .collect();
                (StatusCode::OK, Json(json!({"success": true, "result": result})))
            })
            .post(|State(zone): State<Shared>, headers: HeaderMap, Json(body): Json<Value>| async move {
                if !authorized(&headers, &zone) {
                    return (StatusCode::FORBIDDEN, Json(json!({"success": false, "errors": [{"code": 10000}]})));
                }
                assert_eq!(body["type"], "TXT");
                assert_eq!(body["ttl"], 60);
                let mut zone = zone.lock().unwrap();
                let (name, content) = (body["name"].as_str().unwrap().to_owned(), body["content"].as_str().unwrap().to_owned());
                if zone.records.iter().any(|(_, n, c)| *n == name && *c == content) {
                    return (StatusCode::BAD_REQUEST, Json(json!({"success": false, "errors": [{"code": 81058, "message": "identical record"}]})));
                }
                zone.next += 1;
                let id = format!("r{}", zone.next);
                zone.records.push((id.clone(), name, content));
                (StatusCode::OK, Json(json!({"success": true, "result": {"id": id}})))
            }),
        )
        .route(
            "/zones/z1/dns_records/{id}",
            delete(|State(zone): State<Shared>, headers: HeaderMap, Path(id): Path<String>| async move {
                if !authorized(&headers, &zone) {
                    return (StatusCode::FORBIDDEN, Json(json!({"success": false, "errors": [{"code": 10000}]})));
                }
                zone.lock().unwrap().records.retain(|(i, _, _)| *i != id);
                // Réponse de l'API v4 : `{"success": true, "result": {"id": …}}`.
                (StatusCode::OK, Json(json!({"success": true, "result": {"id": id}})))
            }),
        )
        .with_state(zone.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (url, zone)
}

#[tokio::test]
async fn cloudflare_put_delete() {
    let (url, zone) = fake_cloudflare().await;
    let dns = CloudflareDns::new(&url, "jeton-dns".into(), "z1".into());
    let name = "_acme-challenge.abcdefghijklmnop.maisons.exemple.fr";
    dns.put_txt(name, "valeur-1").await.unwrap();
    dns.put_txt(name, "valeur-2").await.unwrap();
    // Le même enregistrement une seconde fois n'est pas une erreur (nouvel essai de la maison).
    dns.put_txt(name, "valeur-1").await.unwrap();
    assert_eq!(zone.lock().unwrap().records.len(), 2);
    dns.delete_txt(name, "valeur-1").await.unwrap();
    let left: Vec<String> = zone.lock().unwrap().records.iter().map(|r| r.2.clone()).collect();
    assert_eq!(left, ["valeur-2"]);
    dns.delete_txt(name, "absente").await.unwrap();
    // Au plus deux valeurs par nom : la plus ancienne est retirée.
    dns.put_txt(name, "valeur-3").await.unwrap();
    dns.put_txt(name, "valeur-4").await.unwrap();
    let left: Vec<String> = zone.lock().unwrap().records.iter().map(|r| r.2.clone()).collect();
    assert_eq!(left, ["valeur-3", "valeur-4"]);
    assert_eq!(zone.lock().unwrap().bad_auth, 0);
}

#[tokio::test]
async fn cloudflare_error_hides_token() {
    let (url, _) = fake_cloudflare().await;
    let dns = CloudflareDns::new(&url, "mauvais-jeton".into(), "z1".into());
    let err = dns.put_txt("_acme-challenge.x.exemple.fr", "v").await.unwrap_err().to_string();
    assert!(err.contains("403") && !err.contains("mauvais-jeton"), "{err}");
}
