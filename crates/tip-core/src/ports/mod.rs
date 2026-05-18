use crate::domain::{EventFilter, SignedEvent};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerSyncState {
    pub peer_url: String,
    pub last_created_at: i64,
    pub last_id: String,
    pub updated_at: i64,
}

pub trait Clock {
    fn now_unix_seconds(&self) -> i64;
}

pub trait Signer {
    fn public_key(&self) -> String;
    fn sign(&self, message: &[u8]) -> Result<String, CryptoError>;
}

pub trait Verifier {
    fn verify(&self, public_key: &str, message: &[u8], signature: &str) -> Result<(), CryptoError>;
}

pub trait EventStore {
    fn append(&self, event: &SignedEvent) -> Result<(), StoreError>;
    fn get(&self, id: &str) -> Result<Option<SignedEvent>, StoreError>;
    fn query(&self, filter: &EventFilter) -> Result<Vec<SignedEvent>, StoreError>;
}

pub trait PeerSyncStateStore {
    fn get_peer_sync_state(&self, peer_url: &str) -> Result<Option<PeerSyncState>, StoreError>;
    fn put_peer_sync_state(&self, state: &PeerSyncState) -> Result<(), StoreError>;
}

pub trait PeerEventClient {
    fn list_events(&self, filter: &EventFilter) -> Result<Vec<SignedEvent>, PeerError>;
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CryptoError {
    #[error("invalid key: {0}")]
    InvalidKey(String),
    #[error("invalid signature: {0}")]
    InvalidSignature(String),
    #[error("signing failed: {0}")]
    SigningFailed(String),
}

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("store failure: {0}")]
    Failure(String),
}

#[derive(Debug, thiserror::Error)]
pub enum PeerError {
    #[error("peer failure: {0}")]
    Failure(String),
}
