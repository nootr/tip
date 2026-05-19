use assert_cmd::Command as AssertCommand;
use serde_json::Value;
use std::{
    net::TcpListener,
    path::{Path, PathBuf},
    process::{Child, Command as ProcessCommand, Stdio},
    thread,
    time::Duration,
};
use tempfile::TempDir;

#[test]
fn cli_can_submit_to_and_query_from_node() {
    let env = E2eEnv::new();
    let base_url = env.node.base_url.clone();

    let key = env.run_json(&["key", "generate", "--name", "default"]);
    let public_key = key["public_key"].as_str().unwrap();

    let identity_path = env.path("identity.json");
    env.run_ok(&[
        "identity",
        "create",
        "--out",
        identity_path.to_str().unwrap(),
    ]);

    let validation = env.run_json(&[
        "event",
        "validate",
        identity_path.to_str().unwrap(),
        "--node",
        &base_url,
    ]);
    assert_eq!(validation["valid"], true);
    assert!(validation["error"].is_null());

    let empty_query = env.run_json(&["query", "--subject", public_key, "--node", &base_url]);
    assert_eq!(empty_query.as_array().unwrap().len(), 0);

    env.run_ok(&[
        "event",
        "submit",
        identity_path.to_str().unwrap(),
        "--node",
        &base_url,
    ]);

    let query = env.run_json(&["query", "--subject", public_key, "--node", &base_url]);
    let events = query.as_array().unwrap();

    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["type"], "identity.created");
    assert_eq!(events[0]["subject"], public_key);
}

#[test]
fn cli_can_submit_batch_to_and_query_from_node() {
    let env = E2eEnv::new();
    let base_url = env.node.base_url.clone();

    let key = env.run_json(&["key", "generate", "--name", "default"]);
    let public_key = key["public_key"].as_str().unwrap();

    let identity_path = env.path("identity.json");
    env.run_ok(&[
        "identity",
        "create",
        "--out",
        identity_path.to_str().unwrap(),
    ]);

    let claim_path = env.path("claim.json");
    env.run_ok(&[
        "claim",
        "add",
        "github",
        "joris",
        "--out",
        claim_path.to_str().unwrap(),
    ]);

    let attestation_path = env.path("attestation.json");
    env.run_ok(&[
        "attest",
        "issue",
        public_key,
        "trusted_contributor",
        "--out",
        attestation_path.to_str().unwrap(),
    ]);

    let batch_response = env.run_json(&[
        "event",
        "submit-batch",
        identity_path.to_str().unwrap(),
        claim_path.to_str().unwrap(),
        attestation_path.to_str().unwrap(),
        "--node",
        &base_url,
    ]);
    assert_eq!(batch_response["accepted"], 3);
    assert_eq!(batch_response["rejected"], 0);

    let query = env.run_json(&["query", "--subject", public_key, "--node", &base_url]);
    let events = query.as_array().unwrap();

    assert_eq!(events.len(), 3);
    assert!(events
        .iter()
        .any(|event| event["type"] == "identity.created"));
    assert!(events.iter().any(|event| event["type"] == "claim.added"));
    assert!(events
        .iter()
        .any(|event| event["type"] == "attestation.issued"));

    let explanation = env.run_json(&["trust", "explain", public_key, "--node", &base_url]);
    assert_eq!(explanation["subject"], public_key);
    assert_eq!(explanation["active_claims"].as_array().unwrap().len(), 1);
    assert_eq!(
        explanation["active_attestations"].as_array().unwrap().len(),
        1
    );
    assert_eq!(explanation["warnings"].as_array().unwrap().len(), 0);

    let policy_path = env.path("trust-policy.toml");
    std::fs::write(
        &policy_path,
        format!(
            "[trust]\ntrusted_issuers = [\"{}\"]\nrequired_claims = [{{ claim_type = \"github\", value = \"joris\" }}]\naccepted_attestations = [{{ claim = \"trusted_contributor\" }}]\n",
            public_key
        ),
    )
    .unwrap();
    let evaluation = env.run_json(&[
        "trust",
        "evaluate",
        public_key,
        "--policy",
        policy_path.to_str().unwrap(),
        "--node",
        &base_url,
    ]);
    assert_eq!(evaluation["subject"], public_key);
    assert_eq!(evaluation["trusted"], true);
    assert_eq!(evaluation["matched_claims"].as_array().unwrap().len(), 1);
    assert_eq!(
        evaluation["matched_attestations"].as_array().unwrap().len(),
        1
    );
    assert_eq!(evaluation["warnings"].as_array().unwrap().len(), 0);

    let claim_type_only_policy = env.path("claim-type-only-policy.toml");
    std::fs::write(
        &claim_type_only_policy,
        "[trust]\nrequired_claims = [{ claim_type = \"github\" }]\n",
    )
    .unwrap();
    let claim_type_only = env.run_json(&[
        "trust",
        "evaluate",
        public_key,
        "--policy",
        claim_type_only_policy.to_str().unwrap(),
        "--node",
        &base_url,
    ]);
    assert_eq!(claim_type_only["trusted"], true);
    assert_eq!(
        claim_type_only["matched_claims"].as_array().unwrap().len(),
        1
    );

    let missing_claim_policy = env.path("missing-claim-policy.toml");
    std::fs::write(
        &missing_claim_policy,
        "[trust]\nrequired_claims = [{ claim_type = \"domain\", value = \"example.com\" }]\n",
    )
    .unwrap();
    let missing_claim = env.run_json(&[
        "trust",
        "evaluate",
        public_key,
        "--policy",
        missing_claim_policy.to_str().unwrap(),
        "--node",
        &base_url,
    ]);
    assert_eq!(missing_claim["trusted"], false);
    assert_eq!(missing_claim["matched_claims"].as_array().unwrap().len(), 0);
    assert!(missing_claim["warnings"]
        .as_array()
        .unwrap()
        .iter()
        .any(|warning| warning.as_str().unwrap().contains("missing required claim")));

    let untrusted_issuer_policy = env.path("untrusted-issuer-policy.toml");
    std::fs::write(
        &untrusted_issuer_policy,
        "[trust]\ntrusted_issuers = [\"untrusted\"]\naccepted_attestations = [{ claim = \"trusted_contributor\" }]\n",
    )
    .unwrap();
    let untrusted_issuer = env.run_json(&[
        "trust",
        "evaluate",
        public_key,
        "--policy",
        untrusted_issuer_policy.to_str().unwrap(),
        "--node",
        &base_url,
    ]);
    assert_eq!(untrusted_issuer["trusted"], false);
    assert_eq!(
        untrusted_issuer["matched_attestations"]
            .as_array()
            .unwrap()
            .len(),
        0
    );
    assert!(untrusted_issuer["warnings"]
        .as_array()
        .unwrap()
        .iter()
        .any(|warning| warning
            .as_str()
            .unwrap()
            .contains("missing accepted attestation")));

    let empty_policy = env.path("empty-policy.toml");
    std::fs::write(&empty_policy, "[trust]\n").unwrap();
    let empty_policy_evaluation = env.run_json(&[
        "trust",
        "evaluate",
        public_key,
        "--policy",
        empty_policy.to_str().unwrap(),
        "--node",
        &base_url,
    ]);
    assert_eq!(empty_policy_evaluation["trusted"], false);
    assert!(empty_policy_evaluation["warnings"]
        .as_array()
        .unwrap()
        .iter()
        .any(|warning| warning
            .as_str()
            .unwrap()
            .contains("policy has no requirements")));

    let claims = env.run_json(&[
        "query",
        "claims",
        "--subject",
        public_key,
        "--node",
        &base_url,
    ]);
    let claims = claims.as_array().unwrap();
    assert_eq!(claims.len(), 1);
    assert_eq!(claims[0]["type"], "claim.added");

    let attestations = env.run_json(&[
        "query",
        "attestations",
        "--subject",
        public_key,
        "--node",
        &base_url,
    ]);
    let attestations = attestations.as_array().unwrap();
    assert_eq!(attestations.len(), 1);
    assert_eq!(attestations[0]["type"], "attestation.issued");

    let first_page = env.run_json(&[
        "query",
        "--subject",
        public_key,
        "--limit",
        "1",
        "--node",
        &base_url,
    ]);
    let first_page = first_page.as_array().unwrap();
    assert_eq!(first_page.len(), 1);

    let cursor = &first_page[0];
    let second_page = env.run_json(&[
        "query",
        "--subject",
        public_key,
        "--after-created-at",
        &cursor["created_at"].as_i64().unwrap().to_string(),
        "--after-id",
        cursor["id"].as_str().unwrap(),
        "--limit",
        "10",
        "--node",
        &base_url,
    ]);
    let second_page = second_page.as_array().unwrap();
    assert_eq!(second_page.len(), 2);
    assert!(!second_page.iter().any(|event| event["id"] == cursor["id"]));
}

struct E2eEnv {
    temp_dir: TempDir,
    node: NodeProcess,
}

impl E2eEnv {
    fn new() -> Self {
        let temp_dir = tempfile::tempdir().unwrap();
        let node = NodeProcess::start(temp_dir.path());
        Self { temp_dir, node }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.temp_dir.path().join(name)
    }

    fn run_json(&self, args: &[&str]) -> Value {
        serde_json::from_slice(&self.run_ok(args)).unwrap()
    }

    fn run_ok(&self, args: &[&str]) -> Vec<u8> {
        AssertCommand::cargo_bin("tip")
            .unwrap()
            .env("XDG_CONFIG_HOME", self.temp_dir.path().join("config"))
            .args(args)
            .assert()
            .success()
            .get_output()
            .stdout
            .clone()
    }
}

struct NodeProcess {
    child: Child,
    base_url: String,
}

impl NodeProcess {
    fn start(temp_dir: &Path) -> Self {
        let tip_node = assert_cmd::cargo::cargo_bin("tip-node");
        let port = free_port();
        let bind = format!("127.0.0.1:{port}");
        let base_url = format!("http://{bind}");
        let db_path = temp_dir.join("node.sqlite3");
        let key_path = temp_dir.join("node-key.json");

        let child = ProcessCommand::new(tip_node)
            .env("TIP_NODE_BIND", &bind)
            .env("TIP_NODE_DB", &db_path)
            .env("TIP_NODE_KEY", &key_path)
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
