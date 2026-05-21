use axum::{
    body::{to_bytes, Body},
    http::{Method, Request, StatusCode},
    Router,
};
use serde_json::Value;
use std::{
    fs,
    path::PathBuf,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
    time::{SystemTime, UNIX_EPOCH},
};
use tip_core::{
    crypto::Ed25519Keypair,
    ports::{Clock, EventStore, Signer},
    use_cases, SignedEvent,
};
use tip_node::{
    adapters::sqlite_event_store::{KnownPeerUpdate, SqliteEventStore},
    config::NodeMetadata,
    http::{router, AppState},
};
use tower::ServiceExt;

struct FixedClock;

impl Clock for FixedClock {
    fn now_unix_seconds(&self) -> i64 {
        1_700_000_000
    }
}

static DB_COUNTER: AtomicU64 = AtomicU64::new(0);

struct TestDb {
    path: PathBuf,
}

impl TestDb {
    fn new() -> Self {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let counter = DB_COUNTER.fetch_add(1, Ordering::Relaxed);
        Self {
            path: std::env::temp_dir().join(format!(
                "tip-node-http-contract-{}-{}-{}.sqlite3",
                std::process::id(),
                unique,
                counter
            )),
        }
    }

    fn app(&self) -> Router {
        let node_key = Ed25519Keypair::generate();
        let store = SqliteEventStore::open(self.path.to_str().unwrap()).unwrap();
        router(AppState::new(node_key, Arc::new(Mutex::new(store))))
    }

    fn app_with_metadata(&self, metadata: NodeMetadata) -> Router {
        let node_key = Ed25519Keypair::generate();
        let store = SqliteEventStore::open(self.path.to_str().unwrap()).unwrap();
        router(AppState::new_with_metadata(
            node_key,
            Arc::new(Mutex::new(store)),
            metadata,
        ))
    }
}

impl Drop for TestDb {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

#[tokio::test]
async fn health_returns_ok() {
    let db = TestDb::new();
    let response = db
        .app()
        .oneshot(request(Method::GET, "/health", Body::empty()))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(json_body(response).await["status"], "ok");
}

#[tokio::test]
async fn info_returns_node_metadata() {
    let db = TestDb::new();
    let response = db
        .app_with_metadata(NodeMetadata {
            name: Some("Local TIP Node".to_string()),
            description: Some("Community trust registry".to_string()),
            website: Some("https://example.com".to_string()),
            contact: Some("mailto:admin@example.com".to_string()),
        })
        .oneshot(request(Method::GET, "/info", Body::empty()))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response).await;
    assert_eq!(body["version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(body["protocol_version"], "tip/0.1");
    assert!(body["node_public_key"].as_str().unwrap().len() > 40);
    assert_eq!(body["name"], "Local TIP Node");
    assert_eq!(body["description"], "Community trust registry");
    assert_eq!(body["website"], "https://example.com");
    assert_eq!(body["contact"], "mailto:admin@example.com");
}

#[tokio::test]
async fn peers_returns_bounded_known_peer_candidates() {
    let db = TestDb::new();
    let store = SqliteEventStore::open(db.path.to_str().unwrap()).unwrap();
    store
        .upsert_known_peer(&KnownPeerUpdate {
            url: "https://a.example".to_string(),
            claimed_node_public_key: Some("key-a".to_string()),
            name: Some("Peer A".to_string()),
            source_peer_url: Some("https://source.example".to_string()),
            seen_at: 1_700_000_000,
            verified_at: Some(1_700_000_001),
            status: "reachable".to_string(),
            failed: false,
        })
        .unwrap();
    store
        .upsert_known_peer(&KnownPeerUpdate {
            url: "https://b.example".to_string(),
            claimed_node_public_key: Some("key-b".to_string()),
            name: Some("Peer B".to_string()),
            source_peer_url: None,
            seen_at: 1_700_000_002,
            verified_at: Some(1_700_000_003),
            status: "key_mismatch".to_string(),
            failed: true,
        })
        .unwrap();

    let all = db
        .app()
        .oneshot(request(Method::GET, "/peers", Body::empty()))
        .await
        .unwrap();
    assert_eq!(all.status(), StatusCode::OK);
    let all = json_body(all).await;
    assert_eq!(all.as_array().unwrap().len(), 2);
    assert_eq!(all[0]["url"], "https://a.example");
    assert_eq!(all[0]["status"], "reachable");
    assert_eq!(all[0]["failure_count"], 0);
    assert_eq!(all[1]["url"], "https://b.example");
    assert_eq!(all[1]["status"], "key_mismatch");
    assert_eq!(all[1]["failure_count"], 1);

    let filtered = db
        .app()
        .oneshot(request(
            Method::GET,
            "/peers?status=reachable&limit=1",
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(filtered.status(), StatusCode::OK);
    let filtered = json_body(filtered).await;
    assert_eq!(filtered.as_array().unwrap().len(), 1);
    assert_eq!(filtered[0]["url"], "https://a.example");
}

#[tokio::test]
async fn peers_rejects_invalid_query_params() {
    let db = TestDb::new();

    let zero = db
        .app()
        .oneshot(request(Method::GET, "/peers?limit=0", Body::empty()))
        .await
        .unwrap();
    assert_eq!(zero.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        json_body(zero).await["error"],
        "limit must be greater than zero"
    );

    let too_large = db
        .app()
        .oneshot(request(Method::GET, "/peers?limit=501", Body::empty()))
        .await
        .unwrap();
    assert_eq!(too_large.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        json_body(too_large).await["error"],
        "limit must be less than or equal to 500"
    );
}

#[tokio::test]
async fn post_event_accepts_valid_event_and_gets_by_id() {
    let db = TestDb::new();
    let app = db.app();
    let signer = Ed25519Keypair::generate();
    let event = use_cases::create_identity(&FixedClock, &signer).unwrap();

    let post = app
        .clone()
        .oneshot(json_request(Method::POST, "/events", &event))
        .await
        .unwrap();
    assert_eq!(post.status(), StatusCode::ACCEPTED);

    let get = app
        .oneshot(request(
            Method::GET,
            &format!("/events/{}", event.id),
            Body::empty(),
        ))
        .await
        .unwrap();

    assert_eq!(get.status(), StatusCode::OK);
    let returned: SignedEvent = serde_json::from_value(json_body(get).await).unwrap();
    assert_eq!(returned.id, event.id);
}

#[tokio::test]
async fn validate_event_reports_valid_without_storing() {
    let db = TestDb::new();
    let app = db.app();
    let signer = Ed25519Keypair::generate();
    let event = use_cases::create_identity(&FixedClock, &signer).unwrap();

    let response = app
        .clone()
        .oneshot(json_request(Method::POST, "/events/validate", &event))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response).await;
    assert_eq!(body["valid"], true);
    assert!(body["error"].is_null());

    let get = app
        .oneshot(request(
            Method::GET,
            &format!("/events/{}", event.id),
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(get.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn validate_event_reports_reference_and_conflict_errors() {
    let db = TestDb::new();
    let signer = Ed25519Keypair::generate();
    let claim = use_cases::add_claim(&FixedClock, &signer, "github", "joris", None).unwrap();
    let revocation = use_cases::revoke_claim(&FixedClock, &signer, &claim.id).unwrap();

    let missing_reference = db
        .app()
        .oneshot(json_request(Method::POST, "/events/validate", &revocation))
        .await
        .unwrap();

    assert_eq!(missing_reference.status(), StatusCode::OK);
    let body = json_body(missing_reference).await;
    assert_eq!(body["valid"], false);
    assert!(body["error"]
        .as_str()
        .unwrap()
        .contains("referenced claim event not found"));

    let event = use_cases::create_identity(&FixedClock, &signer).unwrap();
    let mut conflicting = event.clone();
    conflicting.signature = "different-signature".to_string();
    let store = SqliteEventStore::open(db.path.to_str().unwrap()).unwrap();
    store.append(&conflicting).unwrap();

    let conflict = db
        .app()
        .oneshot(json_request(Method::POST, "/events/validate", &event))
        .await
        .unwrap();

    assert_eq!(conflict.status(), StatusCode::OK);
    let body = json_body(conflict).await;
    assert_eq!(body["valid"], false);
    assert!(body["error"]
        .as_str()
        .unwrap()
        .contains("event id conflict"));
}

#[tokio::test]
async fn post_events_batch_accepts_valid_events() {
    let db = TestDb::new();
    let app = db.app();
    let signer = Ed25519Keypair::generate();
    let identity = use_cases::create_identity(&FixedClock, &signer).unwrap();
    let claim = use_cases::add_claim(&FixedClock, &signer, "github", "joris", None).unwrap();

    let response = app
        .clone()
        .oneshot(json_request(
            Method::POST,
            "/events/batch",
            &vec![identity.clone(), claim.clone()],
        ))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response).await;
    assert_eq!(body["accepted"], 2);
    assert_eq!(body["rejected"], 0);
    assert_eq!(body["results"].as_array().unwrap().len(), 2);
    assert!(body["results"].as_array().unwrap()[0]["accepted"]
        .as_bool()
        .unwrap());

    let query = app
        .oneshot(request(
            Method::GET,
            &format!("/events?subject={}", signer.public_key()),
            Body::empty(),
        ))
        .await
        .unwrap();
    let events: Vec<SignedEvent> = serde_json::from_value(json_body(query).await).unwrap();
    assert_eq!(events.len(), 2);
}

#[tokio::test]
async fn sync_events_returns_node_local_sequence_pages() {
    let db = TestDb::new();
    let app = db.app();
    let signer = Ed25519Keypair::generate();
    let identity = use_cases::create_identity(&FixedClock, &signer).unwrap();
    let claim = use_cases::add_claim(&FixedClock, &signer, "github", "joris", None).unwrap();

    let post = app
        .clone()
        .oneshot(json_request(
            Method::POST,
            "/events/batch",
            &vec![identity.clone(), claim.clone()],
        ))
        .await
        .unwrap();
    assert_eq!(post.status(), StatusCode::OK);

    let first = app
        .clone()
        .oneshot(request(Method::GET, "/sync/events?limit=1", Body::empty()))
        .await
        .unwrap();
    assert_eq!(first.status(), StatusCode::OK);
    let first = json_body(first).await;
    assert_eq!(first["events"].as_array().unwrap().len(), 1);
    assert_eq!(first["events"][0]["id"], identity.id);
    assert_eq!(first["next_after_sequence"], 1);

    let second = app
        .oneshot(request(
            Method::GET,
            "/sync/events?after_sequence=1&limit=10",
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(second.status(), StatusCode::OK);
    let second = json_body(second).await;
    assert_eq!(second["events"].as_array().unwrap().len(), 1);
    assert_eq!(second["events"][0]["id"], claim.id);
    assert_eq!(second["next_after_sequence"], 2);
}

#[tokio::test]
async fn sync_events_rejects_invalid_cursor_params() {
    let db = TestDb::new();
    let zero_limit = db
        .app()
        .oneshot(request(Method::GET, "/sync/events?limit=0", Body::empty()))
        .await
        .unwrap();
    assert_eq!(zero_limit.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        json_body(zero_limit).await["error"],
        "limit must be greater than zero"
    );

    let negative_sequence = db
        .app()
        .oneshot(request(
            Method::GET,
            "/sync/events?after_sequence=-1",
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(negative_sequence.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        json_body(negative_sequence).await["error"],
        "after_sequence must be greater than or equal to zero"
    );
}

#[tokio::test]
async fn post_events_batch_is_idempotent_for_duplicates() {
    let db = TestDb::new();
    let app = db.app();
    let signer = Ed25519Keypair::generate();
    let event = use_cases::create_identity(&FixedClock, &signer).unwrap();

    let response = app
        .clone()
        .oneshot(json_request(
            Method::POST,
            "/events/batch",
            &vec![event.clone(), event.clone()],
        ))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response).await;
    assert_eq!(body["accepted"], 2);
    assert_eq!(body["rejected"], 0);

    let query = app
        .oneshot(request(
            Method::GET,
            &format!("/events?subject={}", signer.public_key()),
            Body::empty(),
        ))
        .await
        .unwrap();
    let events: Vec<SignedEvent> = serde_json::from_value(json_body(query).await).unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].id, event.id);
}

#[tokio::test]
async fn post_event_rejects_same_id_with_different_stored_content() {
    let db = TestDb::new();
    let signer = Ed25519Keypair::generate();
    let event = use_cases::create_identity(&FixedClock, &signer).unwrap();
    let mut conflicting = event.clone();
    conflicting.signature = "different-signature".to_string();

    let store = SqliteEventStore::open(db.path.to_str().unwrap()).unwrap();
    store.append(&conflicting).unwrap();

    let response = db
        .app()
        .oneshot(json_request(Method::POST, "/events", &event))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(json_body(response).await["error"]
        .as_str()
        .unwrap()
        .contains("event id conflict"));
}

#[tokio::test]
async fn post_events_batch_reports_partial_failures() {
    let db = TestDb::new();
    let app = db.app();
    let signer = Ed25519Keypair::generate();
    let valid = use_cases::create_identity(&FixedClock, &signer).unwrap();
    let mut tampered = use_cases::add_claim(&FixedClock, &signer, "github", "joris", None).unwrap();
    tampered.unsigned.payload["value"] = Value::String("mallory".to_string());

    let response = app
        .clone()
        .oneshot(json_request(
            Method::POST,
            "/events/batch",
            &vec![valid.clone(), tampered],
        ))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response).await;
    assert_eq!(body["accepted"], 1);
    assert_eq!(body["rejected"], 1);
    assert_eq!(body["results"][0]["accepted"], true);
    assert_eq!(body["results"][1]["accepted"], false);
    assert!(body["results"][1]["error"]
        .as_str()
        .unwrap()
        .contains("event id mismatch"));

    let query = app
        .oneshot(request(
            Method::GET,
            &format!("/events?subject={}", signer.public_key()),
            Body::empty(),
        ))
        .await
        .unwrap();
    let events: Vec<SignedEvent> = serde_json::from_value(json_body(query).await).unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].id, valid.id);
}

#[tokio::test]
async fn post_event_rejects_tampered_event() {
    let db = TestDb::new();
    let signer = Ed25519Keypair::generate();
    let mut event = use_cases::add_claim(&FixedClock, &signer, "github", "joris", None).unwrap();
    event.unsigned.payload["value"] = Value::String("mallory".to_string());

    let response = db
        .app()
        .oneshot(json_request(Method::POST, "/events", &event))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(json_body(response).await["error"]
        .as_str()
        .unwrap()
        .contains("event id mismatch"));
}

#[tokio::test]
async fn post_event_rejects_revocation_without_referenced_event() {
    let db = TestDb::new();
    let signer = Ed25519Keypair::generate();
    let claim = use_cases::add_claim(&FixedClock, &signer, "github", "joris", None).unwrap();
    let revocation = use_cases::revoke_claim(&FixedClock, &signer, &claim.id).unwrap();

    let response = db
        .app()
        .oneshot(json_request(Method::POST, "/events", &revocation))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(json_body(response).await["error"]
        .as_str()
        .unwrap()
        .contains("referenced claim event not found"));
}

#[tokio::test]
async fn post_events_batch_accepts_out_of_order_claim_revocation() {
    let db = TestDb::new();
    let app = db.app();
    let signer = Ed25519Keypair::generate();
    let claim = use_cases::add_claim(&FixedClock, &signer, "github", "joris", None).unwrap();
    let revocation = use_cases::revoke_claim(&FixedClock, &signer, &claim.id).unwrap();

    let response = app
        .clone()
        .oneshot(json_request(
            Method::POST,
            "/events/batch",
            &vec![revocation.clone(), claim.clone()],
        ))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response).await;
    assert_eq!(body["accepted"], 2);
    assert_eq!(body["rejected"], 0);

    let query = app
        .oneshot(request(
            Method::GET,
            &format!("/events?subject={}", signer.public_key()),
            Body::empty(),
        ))
        .await
        .unwrap();
    let events: Vec<SignedEvent> = serde_json::from_value(json_body(query).await).unwrap();
    assert_eq!(events.len(), 2);
    assert!(events.iter().any(|event| event.id == claim.id));
    assert!(events.iter().any(|event| event.id == revocation.id));
}

#[tokio::test]
async fn identity_projection_endpoints_return_only_active_claims_and_attestations() {
    let db = TestDb::new();
    let app = db.app();
    let signer = Ed25519Keypair::generate();
    let subject = Ed25519Keypair::generate();

    let active_claim = use_cases::add_claim(&FixedClock, &signer, "github", "joris", None).unwrap();
    let revoked_claim =
        use_cases::add_claim(&FixedClock, &signer, "domain", "example.com", None).unwrap();
    let claim_revocation =
        use_cases::revoke_claim(&FixedClock, &signer, &revoked_claim.id).unwrap();
    let active_attestation = use_cases::issue_attestation(
        &FixedClock,
        &signer,
        subject.public_key(),
        "maintainer",
        None,
    )
    .unwrap();
    let revoked_attestation =
        use_cases::issue_attestation(&FixedClock, &signer, subject.public_key(), "reviewer", None)
            .unwrap();
    let attestation_revocation = use_cases::revoke_attestation(
        &FixedClock,
        &signer,
        subject.public_key(),
        &revoked_attestation.id,
    )
    .unwrap();

    app.clone()
        .oneshot(json_request(
            Method::POST,
            "/events/batch",
            &vec![
                active_claim.clone(),
                revoked_claim.clone(),
                claim_revocation,
                active_attestation.clone(),
                revoked_attestation.clone(),
                attestation_revocation,
            ],
        ))
        .await
        .unwrap();

    let claims = app
        .clone()
        .oneshot(request(
            Method::GET,
            &format!("/identities/{}/claims", signer.public_key()),
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(claims.status(), StatusCode::OK);
    let claims: Vec<SignedEvent> = serde_json::from_value(json_body(claims).await).unwrap();
    assert_eq!(claims.len(), 1);
    assert_eq!(claims[0].id, active_claim.id);

    let attestations = app
        .oneshot(request(
            Method::GET,
            &format!("/identities/{}/attestations", subject.public_key()),
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(attestations.status(), StatusCode::OK);
    let attestations: Vec<SignedEvent> =
        serde_json::from_value(json_body(attestations).await).unwrap();
    assert_eq!(attestations.len(), 1);
    assert_eq!(attestations[0].id, active_attestation.id);
}

#[tokio::test]
async fn query_events_supports_limit_and_cursor() {
    let db = TestDb::new();
    let app = db.app();
    let signer = Ed25519Keypair::generate();
    let identity = use_cases::create_identity(&FixedClock, &signer).unwrap();
    let claim = use_cases::add_claim(&FixedClock, &signer, "github", "joris", None).unwrap();
    let revocation = use_cases::revoke_claim(&FixedClock, &signer, &claim.id).unwrap();

    app.clone()
        .oneshot(json_request(
            Method::POST,
            "/events/batch",
            &vec![identity, claim, revocation],
        ))
        .await
        .unwrap();

    let first_page = app
        .clone()
        .oneshot(request(
            Method::GET,
            &format!("/events?subject={}&limit=1", signer.public_key()),
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(first_page.status(), StatusCode::OK);
    let first_page: Vec<SignedEvent> = serde_json::from_value(json_body(first_page).await).unwrap();
    assert_eq!(first_page.len(), 1);

    let cursor = &first_page[0];
    let second_page = app
        .oneshot(request(
            Method::GET,
            &format!(
                "/events?subject={}&after_created_at={}&after_id={}&limit=10",
                signer.public_key(),
                cursor.unsigned.created_at,
                cursor.id
            ),
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(second_page.status(), StatusCode::OK);
    let second_page: Vec<SignedEvent> =
        serde_json::from_value(json_body(second_page).await).unwrap();
    assert_eq!(second_page.len(), 2);
    assert!(!second_page.iter().any(|event| event.id == cursor.id));
}

#[tokio::test]
async fn query_events_cursor_rejects_after_id_without_timestamp() {
    let db = TestDb::new();
    let response = db
        .app()
        .oneshot(request(
            Method::GET,
            "/events?after_id=sha256:abc",
            Body::empty(),
        ))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(json_body(response).await["error"]
        .as_str()
        .unwrap()
        .contains("after_id requires after_created_at"));
}

#[tokio::test]
async fn query_events_cursor_keeps_type_filters() {
    let db = TestDb::new();
    let app = db.app();
    let signer = Ed25519Keypair::generate();
    let identity = use_cases::create_identity(&FixedClock, &signer).unwrap();
    let claim = use_cases::add_claim(&FixedClock, &signer, "github", "joris", None).unwrap();

    app.clone()
        .oneshot(json_request(
            Method::POST,
            "/events/batch",
            &vec![identity, claim.clone()],
        ))
        .await
        .unwrap();

    let response = app
        .oneshot(request(
            Method::GET,
            &format!(
                "/events?subject={}&type=claim.added&limit=10",
                signer.public_key()
            ),
            Body::empty(),
        ))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let events: Vec<SignedEvent> = serde_json::from_value(json_body(response).await).unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].id, claim.id);
}

#[tokio::test]
async fn query_events_filters_by_subject() {
    let db = TestDb::new();
    let app = db.app();
    let alice = Ed25519Keypair::generate();
    let bob = Ed25519Keypair::generate();
    let alice_event = use_cases::create_identity(&FixedClock, &alice).unwrap();
    let bob_event = use_cases::create_identity(&FixedClock, &bob).unwrap();

    let alice_post = app
        .clone()
        .oneshot(json_request(Method::POST, "/events", &alice_event))
        .await
        .unwrap();
    assert_eq!(alice_post.status(), StatusCode::ACCEPTED);

    let bob_post = app
        .clone()
        .oneshot(json_request(Method::POST, "/events", &bob_event))
        .await
        .unwrap();
    assert_eq!(bob_post.status(), StatusCode::ACCEPTED);

    let response = app
        .oneshot(request(
            Method::GET,
            &format!("/events?subject={}", alice.public_key()),
            Body::empty(),
        ))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let events: Vec<SignedEvent> = serde_json::from_value(json_body(response).await).unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].id, alice_event.id);
}

fn request(method: Method, uri: &str, body: Body) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .body(body)
        .unwrap()
}

fn json_request(method: Method, uri: &str, value: &impl serde::Serialize) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(value).unwrap()))
        .unwrap()
}

async fn json_body(response: axum::response::Response) -> Value {
    let bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
    serde_json::from_slice(&bytes).unwrap()
}
