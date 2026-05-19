use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::{
    str::FromStr,
    sync::{Arc, Mutex},
};
use tip_core::{
    crypto::{Ed25519Keypair, Ed25519Verifier},
    domain::EventType,
    ports::{EventStore, Signer},
    use_cases, EventFilter, SignedEvent, PROTOCOL_VERSION,
};

use crate::adapters::sqlite_event_store::SqliteEventStore;

#[derive(Clone)]
pub struct AppState {
    node_key: Ed25519Keypair,
    store: Arc<Mutex<SqliteEventStore>>,
}

impl AppState {
    pub fn new(node_key: Ed25519Keypair, store: Arc<Mutex<SqliteEventStore>>) -> Self {
        Self { node_key, store }
    }
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/info", get(info))
        .route("/events", post(post_event).get(query_events))
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

    let mut results = Vec::with_capacity(events.len());
    let mut accepted = 0usize;
    let mut rejected = 0usize;

    for event in events {
        let id = event.id.clone();
        match use_cases::submit_event(&*store, &Ed25519Verifier, &event) {
            Ok(()) => {
                accepted += 1;
                results.push(BatchEventResult {
                    id: Some(id),
                    accepted: true,
                    error: None,
                });
            }
            Err(err) => {
                rejected += 1;
                results.push(BatchEventResult {
                    id: Some(id),
                    accepted: false,
                    error: Some(err.to_string()),
                });
            }
        }
    }

    Ok(Json(BatchEventResponse {
        accepted,
        rejected,
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
