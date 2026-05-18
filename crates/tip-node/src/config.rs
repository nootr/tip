use serde::Deserialize;
use std::{fs, path::Path};

#[derive(Debug, Clone, Deserialize)]
pub struct NodeConfig {
    #[serde(default)]
    pub peers: PeerConfig,
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
