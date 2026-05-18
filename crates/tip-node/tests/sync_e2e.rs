use assert_cmd::Command as AssertCommand;
use serde_json::{json, Value};
use std::{
    net::TcpListener,
    path::PathBuf,
    process::{Child, Command as ProcessCommand, Stdio},
    thread,
    time::Duration,
};
use tempfile::TempDir;
use tip_core::{
    crypto::Ed25519Keypair,
    ports::{Clock, EventStore, PeerSyncStateStore, Signer},
    use_cases, EventFilter,
};
use tip_node::adapters::sqlite_event_store::SqliteEventStore;

struct FixedClock;
struct LaterClock;

impl Clock for FixedClock {
    fn now_unix_seconds(&self) -> i64 {
        1_700_000_000
    }
}

impl Clock for LaterClock {
    fn now_unix_seconds(&self) -> i64 {
        1_700_000_001
    }
}

#[test]
fn node_sync_pulls_events_from_peer() {
    let env = SyncEnv::new();
    let peer = NodeProcess::start(env.path("peer.sqlite3"), env.path("peer-key.json"));
    let signer = Ed25519Keypair::generate();
    let identity = use_cases::create_identity(&FixedClock, &signer).unwrap();
    let claim = use_cases::add_claim(&FixedClock, &signer, "github", "joris", None).unwrap();

    submit_events(&peer, &[identity.clone(), claim.clone()]);

    let local_db = env.path("local.sqlite3");
    let summary = sync_peer(&peer, &local_db, 1);
    assert_eq!(
        summary,
        json!({ "pulled": 2, "accepted": 2, "rejected": 0 })
    );

    let store = SqliteEventStore::open(local_db.to_str().unwrap()).unwrap();
    let events = store
        .query(&EventFilter {
            subject: Some(signer.public_key()),
            ..EventFilter::default()
        })
        .unwrap();

    assert_eq!(events.len(), 2);
    assert!(events.iter().any(|event| event.id == identity.id));
    assert!(events.iter().any(|event| event.id == claim.id));
    assert!(store.get_peer_sync_state(&peer.base_url).unwrap().is_some());

    let second = sync_peer(&peer, &local_db, 1);
    assert_eq!(second, json!({ "pulled": 0, "accepted": 0, "rejected": 0 }));

    let later_claim =
        use_cases::add_claim(&LaterClock, &signer, "domain", "example.com", None).unwrap();
    submit_events(&peer, std::slice::from_ref(&later_claim));

    let third = sync_peer(&peer, &local_db, 1);
    assert_eq!(third, json!({ "pulled": 1, "accepted": 1, "rejected": 0 }));

    let events = store
        .query(&EventFilter {
            subject: Some(signer.public_key()),
            ..EventFilter::default()
        })
        .unwrap();
    assert_eq!(events.len(), 3);
    assert!(events.iter().any(|event| event.id == later_claim.id));
}

#[test]
fn node_sync_pulls_events_from_configured_peers() {
    let env = SyncEnv::new();
    let peer_a = NodeProcess::start(env.path("peer-a.sqlite3"), env.path("peer-a-key.json"));
    let peer_b = NodeProcess::start(env.path("peer-b.sqlite3"), env.path("peer-b-key.json"));

    let signer_a = Ed25519Keypair::generate();
    let identity_a = use_cases::create_identity(&FixedClock, &signer_a).unwrap();
    let claim_a = use_cases::add_claim(&FixedClock, &signer_a, "github", "alice", None).unwrap();
    submit_events(&peer_a, &[identity_a.clone(), claim_a.clone()]);

    let signer_b = Ed25519Keypair::generate();
    let identity_b = use_cases::create_identity(&FixedClock, &signer_b).unwrap();
    let claim_b = use_cases::add_claim(&FixedClock, &signer_b, "github", "bob", None).unwrap();
    submit_events(&peer_b, &[identity_b.clone(), claim_b.clone()]);

    let config_path = env.path("tip-node.toml");
    std::fs::write(
        &config_path,
        format!(
            "[peers]\nurls = [\n  \"{}\",\n  \"{}\"\n]\n",
            peer_a.base_url, peer_b.base_url
        ),
    )
    .unwrap();

    let local_db = env.path("local-config.sqlite3");
    let output = AssertCommand::cargo_bin("tip-node")
        .unwrap()
        .args([
            "sync",
            "--config",
            config_path.to_str().unwrap(),
            "--db",
            local_db.to_str().unwrap(),
            "--limit",
            "1",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let summary: Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(summary["pulled"], 4);
    assert_eq!(summary["accepted"], 4);
    assert_eq!(summary["rejected"], 0);
    assert_eq!(summary["peers"].as_array().unwrap().len(), 2);

    let store = SqliteEventStore::open(local_db.to_str().unwrap()).unwrap();
    let events = store.query(&EventFilter::default()).unwrap();
    assert_eq!(events.len(), 4);
    assert!(events.iter().any(|event| event.id == identity_a.id));
    assert!(events.iter().any(|event| event.id == claim_a.id));
    assert!(events.iter().any(|event| event.id == identity_b.id));
    assert!(events.iter().any(|event| event.id == claim_b.id));
}

#[test]
fn node_serve_syncs_configured_peers_on_start_when_enabled() {
    let env = SyncEnv::new();
    let peer = NodeProcess::start(
        env.path("startup-peer.sqlite3"),
        env.path("startup-peer-key.json"),
    );
    let signer = Ed25519Keypair::generate();
    let identity = use_cases::create_identity(&FixedClock, &signer).unwrap();
    let claim = use_cases::add_claim(&FixedClock, &signer, "github", "startup", None).unwrap();
    submit_events(&peer, &[identity.clone(), claim.clone()]);

    let config_path = env.path("startup-tip-node.toml");
    std::fs::write(
        &config_path,
        format!("[peers]\nurls = [\"{}\"]\n", peer.base_url),
    )
    .unwrap();

    let local_db = env.path("startup-local.sqlite3");
    let serving = NodeProcess::start_with_args([
        "serve".to_string(),
        "--bind".to_string(),
        format!("127.0.0.1:{}", free_port()),
        "--db".to_string(),
        local_db.to_str().unwrap().to_string(),
        "--key".to_string(),
        env.path("startup-local-key.json")
            .to_str()
            .unwrap()
            .to_string(),
        "--config".to_string(),
        config_path.to_str().unwrap().to_string(),
        "--sync-on-start".to_string(),
        "--sync-limit".to_string(),
        "1".to_string(),
    ]);

    let store = SqliteEventStore::open(local_db.to_str().unwrap()).unwrap();
    let events = store
        .query(&EventFilter {
            subject: Some(signer.public_key()),
            ..EventFilter::default()
        })
        .unwrap();

    assert_eq!(events.len(), 2);
    assert!(events.iter().any(|event| event.id == identity.id));
    assert!(events.iter().any(|event| event.id == claim.id));
    drop(serving);
}

#[test]
fn node_serve_sync_on_start_requires_configured_peers() {
    let env = SyncEnv::new();
    AssertCommand::cargo_bin("tip-node")
        .unwrap()
        .args([
            "serve",
            "--bind",
            &format!("127.0.0.1:{}", free_port()),
            "--db",
            env.path("missing-config.sqlite3").to_str().unwrap(),
            "--key",
            env.path("missing-config-key.json").to_str().unwrap(),
            "--sync-on-start",
        ])
        .assert()
        .failure()
        .stderr(predicates::str::contains(
            "--sync-on-start requires --config",
        ));
}

fn sync_peer(peer: &NodeProcess, local_db: &std::path::Path, limit: usize) -> Value {
    let output = AssertCommand::cargo_bin("tip-node")
        .unwrap()
        .args([
            "sync",
            "--peer",
            &peer.base_url,
            "--db",
            local_db.to_str().unwrap(),
            "--limit",
            &limit.to_string(),
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    serde_json::from_slice(&output).unwrap()
}

fn submit_events(peer: &NodeProcess, events: &[tip_core::SignedEvent]) {
    let response: Value = reqwest::blocking::Client::new()
        .post(format!("{}/events/batch", peer.base_url))
        .json(events)
        .send()
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .unwrap();
    assert_eq!(response["accepted"], events.len());
}

struct SyncEnv {
    temp_dir: TempDir,
}

impl SyncEnv {
    fn new() -> Self {
        Self {
            temp_dir: tempfile::tempdir().unwrap(),
        }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.temp_dir.path().join(name)
    }
}

struct NodeProcess {
    child: Child,
    base_url: String,
}

impl NodeProcess {
    fn start(db_path: PathBuf, key_path: PathBuf) -> Self {
        let port = free_port();
        let bind = format!("127.0.0.1:{port}");
        Self::start_with_args([
            "serve".to_string(),
            "--bind".to_string(),
            bind,
            "--db".to_string(),
            db_path.to_str().unwrap().to_string(),
            "--key".to_string(),
            key_path.to_str().unwrap().to_string(),
        ])
    }

    fn start_with_args(args: impl IntoIterator<Item = String>) -> Self {
        let args = args.into_iter().collect::<Vec<_>>();
        let bind = args
            .windows(2)
            .find_map(|window| (window[0] == "--bind").then(|| window[1].clone()))
            .expect("--bind arg is required");
        let base_url = format!("http://{bind}");
        let child = ProcessCommand::new(assert_cmd::cargo::cargo_bin("tip-node"))
            .args(args)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();

        let mut process = Self { child, base_url };
        process.wait_until_healthy();
        process
    }

    fn wait_until_healthy(&mut self) {
        for _ in 0..50 {
            if let Some(status) = self.child.try_wait().unwrap() {
                panic!("tip-node exited before becoming healthy: {status}");
            }

            if reqwest::blocking::get(format!("{}/health", self.base_url))
                .map(|response| response.status().is_success())
                .unwrap_or(false)
            {
                return;
            }

            thread::sleep(Duration::from_millis(100));
        }

        panic!("tip-node did not become healthy at {}", self.base_url);
    }
}

impl Drop for NodeProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn free_port() -> u16 {
    TcpListener::bind(("127.0.0.1", 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}
