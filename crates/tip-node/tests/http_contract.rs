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
    ports::{Clock, Signer},
    use_cases, SignedEvent,
};
use tip_node::{
    adapters::sqlite_event_store::SqliteEventStore,
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
        .app()
        .oneshot(request(Method::GET, "/info", Body::empty()))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response).await;
    assert_eq!(body["version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(body["protocol_version"], "tip/0.1");
    assert!(body["node_public_key"].as_str().unwrap().len() > 40);
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
