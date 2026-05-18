use anyhow::Context;
use serde::{Deserialize, Serialize};
use std::{fs, path::Path};
use tip_core::{crypto::Ed25519Keypair, ports::Signer};

#[derive(Serialize, Deserialize)]
struct NodeKeyFile {
    public_key: String,
    seed: String,
    warning: String,
}

pub fn load_or_generate(path: impl AsRef<Path>) -> anyhow::Result<Ed25519Keypair> {
    let path = path.as_ref();
    if path.exists() {
        let raw = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
        let key_file: NodeKeyFile = serde_json::from_str(&raw)?;
        return Ed25519Keypair::from_seed_base64(&key_file.seed).map_err(Into::into);
    }

    let keypair = Ed25519Keypair::generate();
    let key_file = NodeKeyFile {
        public_key: keypair.public_key(),
        seed: keypair.seed_base64(),
        warning: "TIP node identity key; keep private".to_string(),
    };
    let raw = serde_json::to_string_pretty(&key_file)?;
    write_secret_file(path, raw)?;
    Ok(keypair)
}

#[cfg(unix)]
fn write_secret_file(path: &Path, raw: String) -> anyhow::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("create {}", path.display()))?;
    file.write_all(raw.as_bytes())?;
    Ok(())
}

#[cfg(not(unix))]
fn write_secret_file(path: &Path, raw: String) -> anyhow::Result<()> {
    fs::write(path, raw).with_context(|| format!("write {}", path.display()))
}
