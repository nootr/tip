use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use reqwest::Url;
use serde::{Deserialize, Serialize};
use std::{
    str::FromStr,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tip_core::{
    crypto::{Ed25519Keypair, Ed25519Verifier},
    domain::EventType,
    ports::{EventStore, Signer},
    use_cases, EventFilter, SignedEvent, PROTOCOL_VERSION,
};

use crate::{
    adapters::sqlite_event_store::{KnownPeer, KnownPeerUpdate, SqliteEventStore},
    config::NodeMetadata,
};

#[derive(Clone)]
pub struct AppState {
    node_key: Ed25519Keypair,
    store: Arc<Mutex<SqliteEventStore>>,
    metadata: NodeMetadata,
}

impl AppState {
    pub fn new(node_key: Ed25519Keypair, store: Arc<Mutex<SqliteEventStore>>) -> Self {
        Self::new_with_metadata(node_key, store, NodeMetadata::default())
    }

    pub fn new_with_metadata(
        node_key: Ed25519Keypair,
        store: Arc<Mutex<SqliteEventStore>>,
        metadata: NodeMetadata,
    ) -> Self {
        Self {
            node_key,
            store,
            metadata,
        }
    }
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/info", get(info))
        .route("/peers", get(query_peers))
        .route("/peers/announce", post(announce_peer))
        .route("/events", post(post_event).get(query_events))
        .route("/sync/events", get(sync_events))
        .route("/events/validate", post(validate_event))
        .route("/events/batch", post(post_events_batch))
        .route("/events/:id", get(get_event))
        .route("/identities/:pubkey/events", get(identity_events))
        .route("/identities/:pubkey/claims", get(identity_claims))
        .route(
            "/identities/:pubkey/attestations",
            get(identity_attestations),
        )
        .with_state(state)
}

async fn health() -> Json<HealthResponse> {
    Json(HealthResponse { status: "ok" })
}

async fn info(State(state): State<AppState>) -> Json<InfoResponse> {
    Json(InfoResponse {
        node_public_key: state.node_key.public_key(),
        version: env!("CARGO_PKG_VERSION"),
        protocol_version: PROTOCOL_VERSION,
        name: state.metadata.name,
        description: state.metadata.description,
        website: state.metadata.website,
        contact: state.metadata.contact,
    })
}

async fn post_event(
    State(state): State<AppState>,
    Json(event): Json<SignedEvent>,
) -> Result<(StatusCode, Json<SignedEvent>), ApiError> {
    let store = state
        .store
        .lock()
        .map_err(|_| ApiError::internal("store lock poisoned"))?;
    use_cases::submit_event(&*store, &Ed25519Verifier, &event)
        .map_err(|err| ApiError::bad_request(err.to_string()))?;
    Ok((StatusCode::ACCEPTED, Json(event)))
}

async fn validate_event(
    State(state): State<AppState>,
    Json(event): Json<SignedEvent>,
) -> Result<Json<ValidateEventResponse>, ApiError> {
    let store = state
        .store
        .lock()
        .map_err(|_| ApiError::internal("store lock poisoned"))?;

    let response = match use_cases::validate_event_for_submission(&*store, &Ed25519Verifier, &event)
    {
        Ok(()) => ValidateEventResponse {
            valid: true,
            error: None,
        },
        Err(err) => ValidateEventResponse {
            valid: false,
            error: Some(err.to_string()),
        },
    };

    Ok(Json(response))
}

async fn post_events_batch(
    State(state): State<AppState>,
    Json(events): Json<Vec<SignedEvent>>,
) -> Result<Json<BatchEventResponse>, ApiError> {
    let store = state
        .store
        .lock()
        .map_err(|_| ApiError::internal("store lock poisoned"))?;

    let summary = use_cases::submit_events_with_reference_retry(&*store, &Ed25519Verifier, &events);
    let results = summary
        .results
        .into_iter()
        .map(|result| BatchEventResult {
            id: result.id,
            accepted: result.accepted,
            error: result.error,
        })
        .collect();

    Ok(Json(BatchEventResponse {
        accepted: summary.accepted,
        rejected: summary.rejected,
        results,
    }))
}

async fn get_event(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<SignedEvent>, ApiError> {
    let store = state
        .store
        .lock()
        .map_err(|_| ApiError::internal("store lock poisoned"))?;
    match store
        .get(&id)
        .map_err(|err| ApiError::internal(err.to_string()))?
    {
        Some(event) => Ok(Json(event)),
        None => Err(ApiError::not_found("event not found")),
    }
}

async fn announce_peer(
    State(state): State<AppState>,
    Json(request): Json<AnnouncePeerRequest>,
) -> Result<(StatusCode, Json<AnnouncePeerResponse>), ApiError> {
    let url = normalize_peer_url(&request.url)?;

    if let Some(existing) = existing_known_peer(&state, &url)? {
        return Ok((
            StatusCode::OK,
            Json(AnnouncePeerResponse {
                accepted: false,
                url: existing.url,
                claimed_node_public_key: existing.claimed_node_public_key,
                status: existing.status,
            }),
        ));
    }

    let info = fetch_peer_info(&url).await?;
    if let Some(claimed) = &request.claimed_node_public_key {
        if claimed != &info.node_public_key {
            return Err(ApiError::bad_request(
                "claimed_node_public_key does not match announced peer /info",
            ));
        }
    }
    if info.node_public_key == state.node_key.public_key() {
        return Err(ApiError::bad_request("announced peer is this node"));
    }

    let now = now_unix_seconds();
    let name = request.name.or(info.name);
    let update = KnownPeerUpdate {
        url: url.clone(),
        claimed_node_public_key: Some(info.node_public_key.clone()),
        name,
        source_peer_url: None,
        seen_at: now,
        verified_at: Some(now),
        status: "candidate".to_string(),
        failed: false,
    };

    let store = state
        .store
        .lock()
        .map_err(|_| ApiError::internal("store lock poisoned"))?;
    store
        .upsert_known_peer(&update)
        .map_err(|err| ApiError::internal(err.to_string()))?;

    Ok((
        StatusCode::ACCEPTED,
        Json(AnnouncePeerResponse {
            accepted: true,
            url,
            claimed_node_public_key: Some(info.node_public_key),
            status: "candidate".to_string(),
        }),
    ))
}

async fn query_peers(
    State(state): State<AppState>,
    Query(params): Query<PeerQuery>,
) -> Result<Json<Vec<KnownPeer>>, ApiError> {
    let limit = params.limit.unwrap_or(100);
    if limit == 0 {
        return Err(ApiError::bad_request("limit must be greater than zero"));
    }
    if limit > 500 {
        return Err(ApiError::bad_request(
            "limit must be less than or equal to 500",
        ));
    }
    if matches!(params.status.as_deref(), Some("")) {
        return Err(ApiError::bad_request("status must not be empty"));
    }

    let store = state
        .store
        .lock()
        .map_err(|_| ApiError::internal("store lock poisoned"))?;
    let peers = store
        .list_known_peers_filtered(params.status.as_deref(), limit)
        .map_err(|err| ApiError::internal(err.to_string()))?;
    Ok(Json(peers))
}

async fn query_events(
    State(state): State<AppState>,
    Query(params): Query<EventQuery>,
) -> Result<Json<Vec<SignedEvent>>, ApiError> {
    let filter = params.try_into_filter()?;
    let store = state
        .store
        .lock()
        .map_err(|_| ApiError::internal("store lock poisoned"))?;
    let events = use_cases::query_events(&*store, &filter)
        .map_err(|err| ApiError::internal(err.to_string()))?;
    Ok(Json(events))
}

async fn sync_events(
    State(state): State<AppState>,
    Query(params): Query<SyncEventsQuery>,
) -> Result<Json<SyncEventsResponse>, ApiError> {
    let after_sequence = params.after_sequence.unwrap_or(0);
    if after_sequence < 0 {
        return Err(ApiError::bad_request(
            "after_sequence must be greater than or equal to zero",
        ));
    }
    if matches!(params.limit, Some(0)) {
        return Err(ApiError::bad_request("limit must be greater than zero"));
    }

    let store = state
        .store
        .lock()
        .map_err(|_| ApiError::internal("store lock poisoned"))?;
    let sequenced_events = store
        .list_after_sequence(after_sequence, params.limit.unwrap_or(500))
        .map_err(|err| ApiError::internal(err.to_string()))?;
    let next_after_sequence = sequenced_events
        .last()
        .map(|entry| entry.sequence)
        .unwrap_or(after_sequence);
    let events = sequenced_events
        .into_iter()
        .map(|entry| entry.event)
        .collect();

    Ok(Json(SyncEventsResponse {
        events,
        next_after_sequence,
    }))
}

async fn identity_events(
    State(state): State<AppState>,
    Path(pubkey): Path<String>,
) -> Result<Json<Vec<SignedEvent>>, ApiError> {
    let store = state
        .store
        .lock()
        .map_err(|_| ApiError::internal("store lock poisoned"))?;
    let filter = EventFilter {
        subject: Some(pubkey),
        ..EventFilter::default()
    };
    let events = use_cases::query_events(&*store, &filter)
        .map_err(|err| ApiError::internal(err.to_string()))?;
    Ok(Json(events))
}

async fn identity_claims(
    State(state): State<AppState>,
    Path(pubkey): Path<String>,
) -> Result<Json<Vec<SignedEvent>>, ApiError> {
    let store = state
        .store
        .lock()
        .map_err(|_| ApiError::internal("store lock poisoned"))?;
    let claims = use_cases::active_claims(&*store, pubkey)
        .map_err(|err| ApiError::internal(err.to_string()))?;
    Ok(Json(claims))
}

async fn identity_attestations(
    State(state): State<AppState>,
    Path(pubkey): Path<String>,
) -> Result<Json<Vec<SignedEvent>>, ApiError> {
    let store = state
        .store
        .lock()
        .map_err(|_| ApiError::internal("store lock poisoned"))?;
    let attestations = use_cases::active_attestations(&*store, pubkey)
        .map_err(|err| ApiError::internal(err.to_string()))?;
    Ok(Json(attestations))
}

#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
}

#[derive(Serialize)]
struct InfoResponse {
    node_public_key: String,
    version: &'static str,
    protocol_version: &'static str,
    name: Option<String>,
    description: Option<String>,
    website: Option<String>,
    contact: Option<String>,
}

#[derive(Debug, Serialize)]
struct ValidateEventResponse {
    valid: bool,
    error: Option<String>,
}

#[derive(Debug, Serialize)]
struct BatchEventResponse {
    accepted: usize,
    rejected: usize,
    results: Vec<BatchEventResult>,
}

#[derive(Debug, Serialize)]
struct BatchEventResult {
    id: Option<String>,
    accepted: bool,
    error: Option<String>,
}

#[derive(Debug, Serialize)]
struct SyncEventsResponse {
    events: Vec<SignedEvent>,
    next_after_sequence: i64,
}

#[derive(Debug, Deserialize)]
struct SyncEventsQuery {
    after_sequence: Option<i64>,
    limit: Option<usize>,
}

#[derive(Debug, Deserialize)]
struct AnnouncePeerRequest {
    url: String,
    claimed_node_public_key: Option<String>,
    name: Option<String>,
}

#[derive(Debug, Serialize)]
struct AnnouncePeerResponse {
    accepted: bool,
    url: String,
    claimed_node_public_key: Option<String>,
    status: String,
}

#[derive(Debug, Deserialize)]
struct PeerInfoForAnnounce {
    node_public_key: String,
    name: Option<String>,
}

#[derive(Debug, Deserialize)]
struct PeerQuery {
    status: Option<String>,
    limit: Option<usize>,
}

#[derive(Debug, Deserialize)]
struct EventQuery {
    subject: Option<String>,
    issuer: Option<String>,
    #[serde(rename = "type")]
    kind: Option<String>,
    after_created_at: Option<i64>,
    after_id: Option<String>,
    limit: Option<usize>,
}

fn normalize_peer_url(url: &str) -> Result<String, ApiError> {
    let mut parsed = Url::parse(url.trim())
        .map_err(|_| ApiError::bad_request("peer URL must be a valid http(s) URL"))?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return Err(ApiError::bad_request(
            "peer URL must be a valid http(s) URL",
        ));
    }
    parsed.set_fragment(None);
    parsed.set_query(None);
    let normalized = parsed.as_str().trim_end_matches('/').to_string();
    if normalized.is_empty() {
        return Err(ApiError::bad_request(
            "peer URL must be a valid http(s) URL",
        ));
    }
    Ok(normalized)
}

fn existing_known_peer(state: &AppState, url: &str) -> Result<Option<KnownPeer>, ApiError> {
    let store = state
        .store
        .lock()
        .map_err(|_| ApiError::internal("store lock poisoned"))?;
    let peers = store
        .list_known_peers()
        .map_err(|err| ApiError::internal(err.to_string()))?;
    Ok(peers.into_iter().find(|peer| peer.url == url))
}

async fn fetch_peer_info(url: &str) -> Result<PeerInfoForAnnounce, ApiError> {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .map_err(|err| ApiError::internal(err.to_string()))?
        .get(format!("{url}/info"))
        .send()
        .await
        .map_err(|err| ApiError::bad_request(format!("announced peer is not reachable: {err}")))?
        .error_for_status()
        .map_err(|err| ApiError::bad_request(format!("announced peer /info failed: {err}")))?
        .json()
        .await
        .map_err(|err| ApiError::bad_request(format!("announced peer /info is invalid: {err}")))
}

fn now_unix_seconds() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

impl EventQuery {
    fn try_into_filter(self) -> Result<EventFilter, ApiError> {
        let kind = match self.kind {
            Some(kind) => Some(
                EventType::from_str(&kind).map_err(|err| ApiError::bad_request(err.to_string()))?,
            ),
            None => None,
        };
        if self.after_id.is_some() && self.after_created_at.is_none() {
            return Err(ApiError::bad_request(
                "after_id requires after_created_at for cursor queries",
            ));
        }

        if matches!(self.limit, Some(0)) {
            return Err(ApiError::bad_request("limit must be greater than zero"));
        }

        Ok(EventFilter {
            subject: self.subject,
            issuer: self.issuer,
            kind,
            after_created_at: self.after_created_at,
            after_id: self.after_id,
            limit: self.limit,
        })
    }
}

#[derive(Debug, Serialize)]
struct ErrorResponse {
    error: String,
}

#[derive(Debug)]
struct ApiError {
    status: StatusCode,
    message: String,
}

impl ApiError {
    fn bad_request(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message: message.into(),
        }
    }

    fn not_found(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            message: message.into(),
        }
    }

    fn internal(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: message.into(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> axum::response::Response {
        (
            self.status,
            Json(ErrorResponse {
                error: self.message,
            }),
        )
            .into_response()
    }
}
