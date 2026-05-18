use tip_core::{
    domain::EventFilter,
    ports::{PeerError, PeerEventClient},
    SignedEvent,
};

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
}

impl PeerEventClient for HttpPeerEventClient {
    fn list_events(&self, filter: &EventFilter) -> Result<Vec<SignedEvent>, PeerError> {
        let mut request = self.client.get(format!("{}/events", self.base_url));
        let mut query = Vec::new();

        if let Some(subject) = &filter.subject {
            query.push(("subject", subject.clone()));
        }
        if let Some(issuer) = &filter.issuer {
            query.push(("issuer", issuer.clone()));
        }
        if let Some(kind) = &filter.kind {
            query.push(("type", kind.to_string()));
        }
        if let Some(after_created_at) = filter.after_created_at {
            query.push(("after_created_at", after_created_at.to_string()));
        }
        if let Some(after_id) = &filter.after_id {
            query.push(("after_id", after_id.clone()));
        }
        if let Some(limit) = filter.limit {
            query.push(("limit", limit.to_string()));
        }

        if !query.is_empty() {
            request = request.query(&query);
        }

        request
            .send()
            .map_err(to_peer_error)?
            .error_for_status()
            .map_err(to_peer_error)?
            .json()
            .map_err(to_peer_error)
    }
}

fn to_peer_error(error: impl std::fmt::Display) -> PeerError {
    PeerError::Failure(error.to_string())
}
