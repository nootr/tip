use assert_cmd::Command as AssertCommand;
use serde_json::{json, Value};
use std::{
    net::TcpListener,
    path::PathBuf,
    process::{Child, Command as ProcessCommand, Stdio},
    thread,
    time::{Duration, Instant},
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
    let claim = use_cases::add_claim(&LaterClock, &signer, "github", "joris", None).unwrap();

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

    let older_revocation = use_cases::revoke_claim(&FixedClock, &signer, &claim.id).unwrap();
    submit_events(&peer, std::slice::from_ref(&older_revocation));

    let third = sync_peer(&peer, &local_db, 1);
    assert_eq!(third, json!({ "pulled": 1, "accepted": 1, "rejected": 0 }));

    let events = store
        .query(&EventFilter {
            subject: Some(signer.public_key()),
            ..EventFilter::default()
        })
        .unwrap();
    assert_eq!(events.len(), 3);
    assert!(events.iter().any(|event| event.id == older_revocation.id));
    assert!(use_cases::active_claims(&store, signer.public_key())
        .unwrap()
        .is_empty());
    assert_eq!(
        store
            .get_peer_sync_state(&peer.base_url)
            .unwrap()
            .unwrap()
            .last_sequence,
        3
    );

    let peers = list_peers(&local_db);
    assert_eq!(peers.as_array().unwrap().len(), 1);
    assert_eq!(peers[0]["url"], peer.base_url);
    assert_eq!(peers[0]["status"], "reachable");
    assert_eq!(peers[0]["failure_count"], 0);
    assert!(peers[0]["claimed_node_public_key"].as_str().unwrap().len() > 40);
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
    let local_db = env.path("local-config.sqlite3");
    std::fs::write(
        &config_path,
        format!(
            "[node]\ndb = \"{}\"\n\n[[peers.nodes]]\nurl = \"{}\"\nexpected_node_public_key = \"{}\"\nname = \"peer-a\"\n\n[[peers.nodes]]\nurl = \"{}\"\nexpected_node_public_key = \"{}\"\nname = \"peer-b\"\n",
            local_db.display(),
            peer_a.base_url,
            peer_a.node_public_key(),
            peer_b.base_url,
            peer_b.node_public_key()
        ),
    )
    .unwrap();

    let output = AssertCommand::cargo_bin("tip-node")
        .unwrap()
        .args([
            "sync",
            "--config",
            config_path.to_str().unwrap(),
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
fn node_accepts_peer_announce_after_callback_validation() {
    let env = SyncEnv::new();
    let candidate = NodeProcess::start(
        env.path("announce-candidate.sqlite3"),
        env.path("announce-candidate-key.json"),
    );
    let receiver_db = env.path("announce-receiver.sqlite3");
    let receiver = NodeProcess::start(receiver_db.clone(), env.path("announce-receiver-key.json"));
    let candidate_key = candidate.node_public_key();

    let response: Value = reqwest::blocking::Client::new()
        .post(format!("{}/peers/announce", receiver.base_url))
        .json(&json!({
            "url": format!("{}/", candidate.base_url),
            "claimed_node_public_key": candidate_key,
            "name": "announced candidate"
        }))
        .send()
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .unwrap();

    assert_eq!(response["accepted"], true);
    assert_eq!(response["url"], candidate.base_url);
    assert_eq!(response["status"], "candidate");

    let peers = list_peers(&receiver_db);
    let peers = peers.as_array().unwrap();
    assert_eq!(peers.len(), 1);
    assert_eq!(peers[0]["url"], candidate.base_url);
    assert_eq!(
        peers[0]["claimed_node_public_key"],
        response["claimed_node_public_key"]
    );
    assert_eq!(peers[0]["name"], "announced candidate");
    assert_eq!(peers[0]["status"], "candidate");
    assert_eq!(peers[0]["failure_count"], 0);
    assert!(peers[0]["source_peer_url"].is_null());
    assert!(peers[0]["last_verified_at"].as_i64().unwrap() > 0);
}

#[test]
fn node_rejects_peer_announce_with_mismatched_claimed_key() {
    let env = SyncEnv::new();
    let candidate = NodeProcess::start(
        env.path("announce-mismatch-candidate.sqlite3"),
        env.path("announce-mismatch-candidate-key.json"),
    );
    let receiver_db = env.path("announce-mismatch-receiver.sqlite3");
    let receiver = NodeProcess::start(
        receiver_db.clone(),
        env.path("announce-mismatch-receiver-key.json"),
    );

    let response = reqwest::blocking::Client::new()
        .post(format!("{}/peers/announce", receiver.base_url))
        .json(&json!({
            "url": candidate.base_url.clone(),
            "claimed_node_public_key": "wrong-key"
        }))
        .send()
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::BAD_REQUEST);

    let peers = list_peers(&receiver_db);
    assert!(peers.as_array().unwrap().is_empty());
}

#[test]
fn node_sync_ingests_gossiped_peers_as_candidates() {
    let env = SyncEnv::new();
    let source = NodeProcess::start(
        env.path("gossip-source.sqlite3"),
        env.path("gossip-source-key.json"),
    );
    let source_store =
        SqliteEventStore::open(env.path("gossip-source.sqlite3").to_str().unwrap()).unwrap();
    source_store
        .upsert_known_peer(&tip_node::adapters::sqlite_event_store::KnownPeerUpdate {
            url: "https://candidate.example".to_string(),
            claimed_node_public_key: Some("candidate-key".to_string()),
            name: Some("candidate node".to_string()),
            source_peer_url: None,
            seen_at: 1_700_000_010,
            verified_at: None,
            status: "reachable".to_string(),
            failed: false,
        })
        .unwrap();
    source_store
        .upsert_known_peer(&tip_node::adapters::sqlite_event_store::KnownPeerUpdate {
            url: "not a url".to_string(),
            claimed_node_public_key: Some("invalid-key".to_string()),
            name: Some("invalid node".to_string()),
            source_peer_url: None,
            seen_at: 1_700_000_011,
            verified_at: None,
            status: "reachable".to_string(),
            failed: false,
        })
        .unwrap();
    source_store
        .upsert_known_peer(&tip_node::adapters::sqlite_event_store::KnownPeerUpdate {
            url: source.base_url.clone(),
            claimed_node_public_key: Some(source.node_public_key()),
            name: Some("source self".to_string()),
            source_peer_url: None,
            seen_at: 1_700_000_012,
            verified_at: None,
            status: "reachable".to_string(),
            failed: false,
        })
        .unwrap();

    let config_path = env.path("gossip-tip-node.toml");
    let local_db = env.path("gossip-local.sqlite3");
    std::fs::write(
        &config_path,
        format!(
            "[node]\ndb = \"{}\"\n\n[[peers.nodes]]\nurl = \"{}\"\nexpected_node_public_key = \"{}\"\nname = \"source\"\n",
            local_db.display(),
            source.base_url,
            source.node_public_key()
        ),
    )
    .unwrap();

    AssertCommand::cargo_bin("tip-node")
        .unwrap()
        .args(["sync", "--config", config_path.to_str().unwrap()])
        .assert()
        .success();

    let peers = list_peers(&local_db);
    let peers = peers.as_array().unwrap();
    assert_eq!(peers.len(), 2);
    assert!(peers.iter().any(|peer| {
        peer["url"] == source.base_url
            && peer["status"] == "reachable"
            && peer["source_peer_url"].is_null()
    }));
    let candidate = peers
        .iter()
        .find(|peer| peer["url"] == "https://candidate.example")
        .unwrap();
    assert_eq!(candidate["claimed_node_public_key"], "candidate-key");
    assert_eq!(candidate["name"], "candidate node");
    assert_eq!(candidate["source_peer_url"], source.base_url);
    assert_eq!(candidate["status"], "candidate");
    assert_eq!(candidate["failure_count"], 0);
    assert!(candidate["last_verified_at"].is_null());
    assert!(!peers.iter().any(|peer| peer["url"] == "not a url"));

    let ad_hoc_db = env.path("gossip-ad-hoc-local.sqlite3");
    let ad_hoc_summary = sync_peer(&source, &ad_hoc_db, 500);
    assert_eq!(
        ad_hoc_summary,
        json!({ "pulled": 0, "accepted": 0, "rejected": 0 })
    );
    let ad_hoc_peers = list_peers(&ad_hoc_db);
    let ad_hoc_peers = ad_hoc_peers.as_array().unwrap();
    assert_eq!(ad_hoc_peers.len(), 1);
    assert_eq!(ad_hoc_peers[0]["url"], source.base_url);
    assert_eq!(ad_hoc_peers[0]["status"], "reachable");
}

#[test]
fn node_serve_periodic_sequence_sync_catches_late_older_events() {
    let env = SyncEnv::new();
    let peer = NodeProcess::start(
        env.path("periodic-peer.sqlite3"),
        env.path("periodic-peer-key.json"),
    );
    let signer = Ed25519Keypair::generate();
    let claim = use_cases::add_claim(&LaterClock, &signer, "github", "periodic", None).unwrap();
    submit_events(&peer, std::slice::from_ref(&claim));

    let config_path = env.path("periodic-tip-node.toml");
    let local_db = env.path("periodic-local.sqlite3");
    let bind = format!("127.0.0.1:{}", free_port());
    std::fs::write(
        &config_path,
        format!(
            "[node]\nbind = \"{}\"\ndb = \"{}\"\nkey = \"{}\"\n\n[sync]\nlimit = 1\nperiodic_seconds = 1\n\n[[peers.nodes]]\nurl = \"{}\"\nexpected_node_public_key = \"{}\"\nname = \"periodic-peer\"\n",
            bind,
            local_db.display(),
            env.path("periodic-local-key.json").display(),
            peer.base_url,
            peer.node_public_key()
        ),
    )
    .unwrap();

    let serving = NodeProcess::start_with_args_and_base_url(
        [
            "serve".to_string(),
            "--config".to_string(),
            config_path.to_str().unwrap().to_string(),
        ],
        format!("http://{}", bind),
    );

    wait_for_store(&local_db, |store| store.get(&claim.id).unwrap().is_some());

    let revocation = use_cases::revoke_claim(&FixedClock, &signer, &claim.id).unwrap();
    submit_events(&peer, std::slice::from_ref(&revocation));
    let subject = signer.public_key();
    wait_for_store(&local_db, |store| {
        store.get(&revocation.id).unwrap().is_some()
            && use_cases::active_claims(store, &subject)
                .unwrap()
                .is_empty()
    });

    drop(serving);
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
    let local_db = env.path("startup-local.sqlite3");
    let bind = format!("127.0.0.1:{}", free_port());
    std::fs::write(
        &config_path,
        format!(
            "[node]\nbind = \"{}\"\ndb = \"{}\"\nkey = \"{}\"\n\n[sync]\non_start = true\nlimit = 1\n\n[[peers.nodes]]\nurl = \"{}\"\nexpected_node_public_key = \"{}\"\nname = \"startup-peer\"\n",
            bind,
            local_db.display(),
            env.path("startup-local-key.json").display(),
            peer.base_url,
            peer.node_public_key()
        ),
    )
    .unwrap();

    let serving = NodeProcess::start_with_args_and_base_url(
        [
            "serve".to_string(),
            "--config".to_string(),
            config_path.to_str().unwrap().to_string(),
        ],
        format!("http://{}", bind),
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
    drop(serving);
}

#[test]
fn node_sync_rejects_mismatched_pinned_peer_identity() {
    let env = SyncEnv::new();
    let peer = NodeProcess::start(
        env.path("pinned-peer.sqlite3"),
        env.path("pinned-peer-key.json"),
    );
    let config_path = env.path("pinned-tip-node.toml");
    let local_db = env.path("pinned-local.sqlite3");
    std::fs::write(
        &config_path,
        format!(
            "[node]\ndb = \"{}\"\n\n[[peers.nodes]]\nurl = \"{}\"\nexpected_node_public_key = \"wrong-key\"\nname = \"pinned-peer\"\n",
            local_db.display(),
            peer.base_url,
        ),
    )
    .unwrap();

    AssertCommand::cargo_bin("tip-node")
        .unwrap()
        .args(["sync", "--config", config_path.to_str().unwrap()])
        .assert()
        .failure()
        .stderr(predicates::str::contains("node public key mismatch"));

    let peers = list_peers(&local_db);
    assert_eq!(peers.as_array().unwrap().len(), 1);
    assert_eq!(peers[0]["url"], peer.base_url);
    assert_eq!(peers[0]["status"], "key_mismatch");
    assert_eq!(peers[0]["failure_count"], 1);
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
            "configured sync requires [[peers.nodes]] entries",
        ));
}

fn list_peers(local_db: &std::path::Path) -> Value {
    let output = AssertCommand::cargo_bin("tip-node")
        .unwrap()
        .args(["peers", "list", "--db", local_db.to_str().unwrap()])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    serde_json::from_slice(&output).unwrap()
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

fn wait_for_store(path: &std::path::Path, predicate: impl Fn(&SqliteEventStore) -> bool) {
    let deadline = Instant::now() + Duration::from_secs(10);

    loop {
        let store = SqliteEventStore::open(path.to_str().unwrap()).unwrap();
        if predicate(&store) {
            return;
        }

        if Instant::now() >= deadline {
            panic!(
                "timed out waiting for store condition at {}",
                path.display()
            );
        }

        thread::sleep(Duration::from_millis(100));
    }
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
        Self::start_with_args_and_base_url(args, format!("http://{bind}"))
    }

    fn start_with_args_and_base_url(
        args: impl IntoIterator<Item = String>,
        base_url: String,
    ) -> Self {
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

    fn node_public_key(&self) -> String {
        reqwest::blocking::get(format!("{}/info", self.base_url))
            .unwrap()
            .error_for_status()
            .unwrap()
            .json::<Value>()
            .unwrap()["node_public_key"]
            .as_str()
            .unwrap()
            .to_string()
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
