use serde::Deserialize;
use tip_core::{
    ports::{PeerError, PeerEventClient, PeerEventPage},
    SignedEvent,
};

#[derive(Debug, Clone, Deserialize)]
pub struct PeerNodeInfo {
    pub node_public_key: String,
}

#[derive(Debug, Clone, Deserialize)]
struct SyncEventsResponse {
    events: Vec<SignedEvent>,
    next_after_sequence: i64,
}

pub struct HttpPeerEventClient {
    base_url: String,
    client: reqwest::blocking::Client,
}

impl HttpPeerEventClient {
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            client: reqwest::blocking::Client::new(),
        }
    }

    pub fn node_info(&self) -> Result<PeerNodeInfo, PeerError> {
        self.client
            .get(format!("{}/info", self.base_url))
            .send()
            .map_err(to_peer_error)?
            .error_for_status()
            .map_err(to_peer_error)?
            .json()
            .map_err(to_peer_error)
    }
}

impl PeerEventClient for HttpPeerEventClient {
    fn list_events_after_sequence(
        &self,
        after_sequence: i64,
        limit: usize,
    ) -> Result<PeerEventPage, PeerError> {
        let response: SyncEventsResponse = self
            .client
            .get(format!("{}/sync/events", self.base_url))
            .query(&[
                ("after_sequence", after_sequence.to_string()),
                ("limit", limit.to_string()),
            ])
            .send()
            .map_err(to_peer_error)?
            .error_for_status()
            .map_err(to_peer_error)?
            .json()
            .map_err(to_peer_error)?;

        Ok(PeerEventPage {
            events: response.events,
            next_after_sequence: response.next_after_sequence,
        })
    }
}

fn to_peer_error(error: impl std::fmt::Display) -> PeerError {
    PeerError::Failure(error.to_string())
}
