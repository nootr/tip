use assert_cmd::Command;
use serde_json::Value;
use std::path::Path;
use tempfile::TempDir;

#[test]
fn key_generate_identity_create_and_verify_work() {
    let env = CliEnv::new();
    let key = env.key_generate("default");
    let public_key = key["public_key"].as_str().unwrap();

    let identity_path = env.path("identity.json");
    env.run_ok(&[
        "identity",
        "create",
        "--out",
        identity_path.to_str().unwrap(),
    ]);

    let identity = read_json(&identity_path);
    assert_eq!(identity["type"], "identity.created");
    assert_eq!(identity["subject"], public_key);
    assert_eq!(identity["issuer"], public_key);

    env.verify_event(&identity_path);
}

#[test]
fn claim_and_attestation_commands_create_verifiable_events() {
    let env = CliEnv::new();
    env.key_generate("default");
    let subject = env.key_generate("subject");
    let subject_public_key = subject["public_key"].as_str().unwrap();

    let claim_path = env.path("claim.json");
    env.run_ok(&[
        "claim",
        "add",
        "github",
        "joris",
        "--proof-url",
        "https://gist.github.com/joris/tip-proof",
        "--out",
        claim_path.to_str().unwrap(),
    ]);
    env.verify_event(&claim_path);
    let claim = read_json(&claim_path);
    assert_eq!(claim["type"], "claim.added");
    assert_eq!(claim["payload"]["claim_type"], "github");
    assert_eq!(claim["payload"]["value"], "joris");

    let claim_revocation_path = env.path("claim-revoked.json");
    env.run_ok(&[
        "claim",
        "revoke",
        claim["id"].as_str().unwrap(),
        "--out",
        claim_revocation_path.to_str().unwrap(),
    ]);
    env.verify_event(&claim_revocation_path);
    let claim_revocation = read_json(&claim_revocation_path);
    assert_eq!(claim_revocation["type"], "claim.revoked");
    assert_eq!(claim_revocation["payload"]["claim_id"], claim["id"]);

    let attestation_path = env.path("attestation.json");
    env.run_ok(&[
        "attest",
        "issue",
        subject_public_key,
        "trusted_contributor",
        "--message",
        "Useful open-source contributor",
        "--out",
        attestation_path.to_str().unwrap(),
    ]);
    env.verify_event(&attestation_path);
    let attestation = read_json(&attestation_path);
    assert_eq!(attestation["type"], "attestation.issued");
    assert_eq!(attestation["subject"], subject_public_key);
    assert_eq!(attestation["payload"]["claim"], "trusted_contributor");

    let attestation_revocation_path = env.path("attestation-revoked.json");
    env.run_ok(&[
        "attest",
        "revoke",
        subject_public_key,
        attestation["id"].as_str().unwrap(),
        "--out",
        attestation_revocation_path.to_str().unwrap(),
    ]);
    env.verify_event(&attestation_revocation_path);
    let attestation_revocation = read_json(&attestation_revocation_path);
    assert_eq!(attestation_revocation["type"], "attestation.revoked");
    assert_eq!(
        attestation_revocation["payload"]["attestation_id"],
        attestation["id"]
    );
}

#[test]
fn query_command_exposes_cursor_flags() {
    let env = CliEnv::new();
    let output = env.run_ok(&["query", "--help"]);
    let help = String::from_utf8(output).unwrap();

    assert!(help.contains("--after-created-at"));
    assert!(help.contains("--after-id"));
    assert!(help.contains("--limit"));
    assert!(help.contains("claims"));
    assert!(help.contains("attestations"));

    let claims = String::from_utf8(env.run_ok(&["query", "claims", "--help"])).unwrap();
    assert!(claims.contains("Usage: tip query claims"));
    assert!(claims.contains("--subject"));
    assert!(claims.contains("--node"));
}

#[test]
fn event_node_commands_are_available() {
    let env = CliEnv::new();

    let validate = String::from_utf8(env.run_ok(&["event", "validate", "--help"])).unwrap();
    assert!(validate.contains("Usage: tip event validate"));
    assert!(validate.contains("--node"));

    let submit_batch = String::from_utf8(env.run_ok(&["event", "submit-batch", "--help"])).unwrap();
    assert!(submit_batch.contains("Usage: tip event submit-batch"));
    assert!(submit_batch.contains("--node"));
}

#[test]
fn trust_explain_command_is_available() {
    let env = CliEnv::new();
    let explain = String::from_utf8(env.run_ok(&["trust", "explain", "--help"])).unwrap();

    assert!(explain.contains("Usage: tip trust explain"));
    assert!(explain.contains("--node"));
}

struct CliEnv {
    temp_dir: TempDir,
}

impl CliEnv {
    fn new() -> Self {
        Self {
            temp_dir: tempfile::tempdir().unwrap(),
        }
    }

    fn path(&self, name: &str) -> std::path::PathBuf {
        self.temp_dir.path().join(name)
    }

    fn key_generate(&self, name: &str) -> Value {
        self.run_json(&["key", "generate", "--name", name])
    }

    fn verify_event(&self, path: &Path) {
        let output = self.run_ok(&["event", "verify", path.to_str().unwrap()]);
        assert_eq!(String::from_utf8(output).unwrap().trim(), "ok");
    }

    fn run_json(&self, args: &[&str]) -> Value {
        serde_json::from_slice(&self.run_ok(args)).unwrap()
    }

    fn run_ok(&self, args: &[&str]) -> Vec<u8> {
        let output = Command::cargo_bin("tip")
            .unwrap()
            .env("XDG_CONFIG_HOME", self.temp_dir.path().join("config"))
            .args(args)
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();
        output
    }
}

fn read_json(path: &Path) -> Value {
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}
