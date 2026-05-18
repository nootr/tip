use anyhow::{bail, Context};
use serde::{Deserialize, Serialize};
use std::{fs, path::PathBuf};
use tip_core::{crypto::Ed25519Keypair, ports::Signer};

pub struct FileKeyStore {
    keys_dir: PathBuf,
}

#[derive(Serialize, Deserialize)]
struct KeyFile {
    public_key: String,
    seed: String,
    warning: String,
}

impl FileKeyStore {
    pub fn default() -> anyhow::Result<Self> {
        let config_home = std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".config")))
            .context("cannot determine config directory; set XDG_CONFIG_HOME or HOME")?;

        let keys_dir = config_home.join("tip").join("keys");
        fs::create_dir_all(&keys_dir).with_context(|| format!("create {}", keys_dir.display()))?;
        Ok(Self { keys_dir })
    }

    pub fn generate(&self, name: &str) -> anyhow::Result<String> {
        validate_name(name)?;
        let path = self.path_for(name);
        if path.exists() {
            bail!("key already exists: {}", path.display());
        }

        let keypair = Ed25519Keypair::generate();
        let key_file = KeyFile {
            public_key: keypair.public_key(),
            seed: keypair.seed_base64(),
            warning: "v1 local development key; not hardened wallet storage".to_string(),
        };
        let raw = serde_json::to_string_pretty(&key_file)?;
        write_secret_file(&path, raw)?;
        Ok(key_file.public_key)
    }

    pub fn load(&self, name: &str) -> anyhow::Result<Ed25519Keypair> {
        validate_name(name)?;
        let path = self.path_for(name);
        let raw = fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
        let key_file: KeyFile = serde_json::from_str(&raw)?;
        Ed25519Keypair::from_seed_base64(&key_file.seed).map_err(Into::into)
    }

    fn path_for(&self, name: &str) -> PathBuf {
        self.keys_dir.join(format!("{}.json", name))
    }
}

fn validate_name(name: &str) -> anyhow::Result<()> {
    let valid = !name.is_empty()
        && name
            .bytes()
            .all(|b| matches!(b, b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'_'));
    if !valid {
        bail!("key name may only contain letters, digits, '-' and '_'");
    }
    Ok(())
}

#[cfg(unix)]
fn write_secret_file(path: &PathBuf, raw: String) -> anyhow::Result<()> {
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
fn write_secret_file(path: &PathBuf, raw: String) -> anyhow::Result<()> {
    fs::write(path, raw).with_context(|| format!("write {}", path.display()))
}
