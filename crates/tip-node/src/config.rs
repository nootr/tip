use serde::Deserialize;
use std::{fs, path::Path};

#[derive(Debug, Clone, Default, Deserialize)]
pub struct NodeConfig {
    #[serde(default)]
    pub node: RuntimeNodeConfig,
    #[serde(default)]
    pub sync: SyncConfig,
    #[serde(default)]
    pub peers: PeerConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RuntimeNodeConfig {
    pub bind: Option<String>,
    pub db: Option<String>,
    pub key: Option<String>,
}

impl Default for RuntimeNodeConfig {
    fn default() -> Self {
        Self {
            bind: Some("127.0.0.1:8080".to_string()),
            db: Some("tip-node.sqlite3".to_string()),
            key: Some("tip-node-key.json".to_string()),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct SyncConfig {
    pub on_start: Option<bool>,
    pub limit: Option<usize>,
    pub from_beginning: Option<bool>,
}

impl Default for SyncConfig {
    fn default() -> Self {
        Self {
            on_start: Some(false),
            limit: Some(500),
            from_beginning: Some(false),
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct PeerConfig {
    #[serde(default)]
    pub urls: Vec<String>,
}

impl NodeConfig {
    pub fn load(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let path = path.as_ref();
        let raw = fs::read_to_string(path)?;
        Ok(toml::from_str(&raw)?)
    }
}
