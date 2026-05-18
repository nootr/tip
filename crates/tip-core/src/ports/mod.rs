use crate::domain::{EventFilter, SignedEvent};

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
