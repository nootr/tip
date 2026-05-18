use assert_cmd::Command as AssertCommand;
use serde_json::{json, Value};
use std::{
    net::TcpListener,
    path::{Path, PathBuf},
    process::{Child, Command as ProcessCommand, Stdio},
    thread,
    time::Duration,
};
use tempfile::TempDir;
use tip_core::{
    crypto::Ed25519Keypair,
    ports::{Clock, EventStore, Signer},
    use_cases, EventFilter,
};
use tip_node::adapters::sqlite_event_store::SqliteEventStore;

struct FixedClock;

impl Clock for FixedClock {
    fn now_unix_seconds(&self) -> i64 {
        1_700_000_000
    }
}

#[test]
fn node_sync_pulls_events_from_peer() {
    let env = SyncEnv::new();
    let peer = NodeProcess::start(env.path("peer.sqlite3"), env.path("peer-key.json"));
    let signer = Ed25519Keypair::generate();
    let identity = use_cases::create_identity(&FixedClock, &signer).unwrap();
    let claim = use_cases::add_claim(&FixedClock, &signer, "github", "joris", None).unwrap();

    let response: Value = reqwest::blocking::Client::new()
        .post(format!("{}/events/batch", peer.base_url))
        .json(&vec![identity.clone(), claim.clone()])
        .send()
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .unwrap();
    assert_eq!(response["accepted"], 2);

    let local_db = env.path("local.sqlite3");
    let output = AssertCommand::cargo_bin("tip-node")
        .unwrap()
        .args([
            "sync",
            "--peer",
            &peer.base_url,
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
        let base_url = format!("http://{bind}");
        let child = ProcessCommand::new(tip_node_binary())
            .args([
                "serve",
                "--bind",
                &bind,
                "--db",
                db_path.to_str().unwrap(),
                "--key",
                key_path.to_str().unwrap(),
            ])
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

fn tip_node_binary() -> PathBuf {
    let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();

    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
    let status = ProcessCommand::new(cargo)
        .args(["build", "-p", "tip-node"])
        .current_dir(workspace_root)
        .status()
        .unwrap();
    assert!(status.success());

    let target_dir = std::env::var_os("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| workspace_root.join("target"));
    let target_dir = if target_dir.is_absolute() {
        target_dir
    } else {
        workspace_root.join(target_dir)
    };

    target_dir
        .join("debug")
        .join(format!("tip-node{}", std::env::consts::EXE_SUFFIX))
}

fn free_port() -> u16 {
    TcpListener::bind(("127.0.0.1", 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}
