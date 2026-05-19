use serde_json::{json, Value};
use std::collections::HashSet;

use crate::{
    domain::{DomainError, EventFilter, EventType, SignedEvent, UnsignedEvent},
    ports::{
        Clock, CryptoError, EventStore, PeerError, PeerEventClient, PeerSyncState,
        PeerSyncStateStore, Signer, StoreError, Verifier,
    },
};

#[derive(Debug, thiserror::Error)]
pub enum UseCaseError {
    #[error(transparent)]
    Domain(#[from] DomainError),
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error(transparent)]
    Peer(#[from] PeerError),
}

pub fn create_identity(
    clock: &impl Clock,
    signer: &impl Signer,
) -> Result<SignedEvent, UseCaseError> {
    let public_key = signer.public_key();
    sign_event(
        signer,
        UnsignedEvent::new(
            EventType::IdentityCreated,
            public_key.clone(),
            public_key,
            clock.now_unix_seconds(),
            json!({}),
        ),
    )
}

pub fn add_claim(
    clock: &impl Clock,
    signer: &impl Signer,
    claim_type: impl Into<String>,
    value: impl Into<String>,
    proof: Option<Value>,
) -> Result<SignedEvent, UseCaseError> {
    let public_key = signer.public_key();
    let mut payload = json!({
        "claim_type": claim_type.into(),
        "value": value.into(),
    });

    if let Some(proof) = proof {
        payload["proof"] = proof;
    }

    sign_event(
        signer,
        UnsignedEvent::new(
            EventType::ClaimAdded,
            public_key.clone(),
            public_key,
            clock.now_unix_seconds(),
            payload,
        ),
    )
}

pub fn revoke_claim(
    clock: &impl Clock,
    signer: &impl Signer,
    claim_id: impl Into<String>,
) -> Result<SignedEvent, UseCaseError> {
    let public_key = signer.public_key();
    sign_event(
        signer,
        UnsignedEvent::new(
            EventType::ClaimRevoked,
            public_key.clone(),
            public_key,
            clock.now_unix_seconds(),
            json!({ "claim_id": claim_id.into() }),
        ),
    )
}

pub fn issue_attestation(
    clock: &impl Clock,
    signer: &impl Signer,
    subject: impl Into<String>,
    claim: impl Into<String>,
    message: Option<String>,
) -> Result<SignedEvent, UseCaseError> {
    let issuer = signer.public_key();
    let mut payload = json!({ "claim": claim.into() });
    if let Some(message) = message {
        payload["message"] = Value::String(message);
    }

    sign_event(
        signer,
        UnsignedEvent::new(
            EventType::AttestationIssued,
            subject.into(),
            issuer,
            clock.now_unix_seconds(),
            payload,
        ),
    )
}

pub fn revoke_attestation(
    clock: &impl Clock,
    signer: &impl Signer,
    subject: impl Into<String>,
    attestation_id: impl Into<String>,
) -> Result<SignedEvent, UseCaseError> {
    sign_event(
        signer,
        UnsignedEvent::new(
            EventType::AttestationRevoked,
            subject.into(),
            signer.public_key(),
            clock.now_unix_seconds(),
            json!({ "attestation_id": attestation_id.into() }),
        ),
    )
}

pub fn sign_event(
    signer: &impl Signer,
    unsigned: UnsignedEvent,
) -> Result<SignedEvent, UseCaseError> {
    unsigned.validate_shape()?;
    let canonical = unsigned.canonical_bytes()?;
    let id = unsigned.event_id()?;
    let signature = signer.sign(&canonical)?;
    Ok(SignedEvent {
        id,
        unsigned,
        signature,
    })
}

pub fn verify_event(event: &SignedEvent, verifier: &impl Verifier) -> Result<(), UseCaseError> {
    event.validate_id_and_shape()?;
    verifier.verify(
        &event.unsigned.issuer,
        &event.unsigned.canonical_bytes()?,
        &event.signature,
    )?;
    Ok(())
}

pub fn submit_event(
    store: &impl EventStore,
    verifier: &impl Verifier,
    event: &SignedEvent,
) -> Result<(), UseCaseError> {
    validate_event_for_submission(store, verifier, event)?;
    store.append(event)?;
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchSubmitSummary {
    pub accepted: usize,
    pub rejected: usize,
    pub results: Vec<BatchSubmitResult>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchSubmitResult {
    pub id: Option<String>,
    pub accepted: bool,
    pub error: Option<String>,
}

pub fn submit_events_with_reference_retry(
    store: &impl EventStore,
    verifier: &impl Verifier,
    events: &[SignedEvent],
) -> BatchSubmitSummary {
    let mut results = vec![None; events.len()];
    let mut pending = Vec::new();

    for (index, event) in events.iter().enumerate() {
        match submit_event(store, verifier, event) {
            Ok(()) => results[index] = Some(accepted_result(event)),
            Err(err) if is_missing_reference_error(&err) => pending.push(index),
            Err(err) => results[index] = Some(rejected_result(event, err)),
        }
    }

    while !pending.is_empty() {
        let mut next_pending = Vec::new();
        let pending_len = pending.len();

        for index in pending {
            let event = &events[index];
            match submit_event(store, verifier, event) {
                Ok(()) => results[index] = Some(accepted_result(event)),
                Err(err) if is_missing_reference_error(&err) => next_pending.push(index),
                Err(err) => results[index] = Some(rejected_result(event, err)),
            }
        }

        if next_pending.len() == pending_len {
            for index in next_pending {
                let event = &events[index];
                let error = validate_event_for_submission(store, verifier, event)
                    .err()
                    .map(|err| err.to_string())
                    .unwrap_or_else(|| "event could not be submitted".to_string());
                results[index] = Some(BatchSubmitResult {
                    id: Some(event.id.clone()),
                    accepted: false,
                    error: Some(error),
                });
            }
            break;
        }

        pending = next_pending;
    }

    let results = results
        .into_iter()
        .map(|result| result.expect("every batch event has a result"))
        .collect::<Vec<_>>();
    let accepted = results.iter().filter(|result| result.accepted).count();
    let rejected = results.len() - accepted;

    BatchSubmitSummary {
        accepted,
        rejected,
        results,
    }
}

pub fn validate_event_for_submission(
    store: &impl EventStore,
    verifier: &impl Verifier,
    event: &SignedEvent,
) -> Result<(), UseCaseError> {
    verify_event(event, verifier)?;
    if event_already_stored(store, event)? {
        return Ok(());
    }
    validate_event_references(store, event)?;
    Ok(())
}

pub fn validate_event_references(
    store: &impl EventStore,
    event: &SignedEvent,
) -> Result<(), UseCaseError> {
    match event.unsigned.kind {
        EventType::ClaimRevoked => {
            let claim_id = payload_string(event, "claim_id")?;
            let claim = require_referenced_event(store, claim_id, "claim")?;

            if claim.unsigned.kind != EventType::ClaimAdded {
                return Err(invalid_event(format!(
                    "claim.revoked references {} event {}",
                    claim.unsigned.kind, claim.id
                )));
            }

            if claim.unsigned.subject != event.unsigned.subject {
                return Err(invalid_event(
                    "claim.revoked subject must match referenced claim subject",
                ));
            }

            if claim.unsigned.issuer != event.unsigned.issuer {
                return Err(invalid_event(
                    "claim.revoked issuer must match referenced claim issuer",
                ));
            }
        }
        EventType::AttestationRevoked => {
            let attestation_id = payload_string(event, "attestation_id")?;
            let attestation = require_referenced_event(store, attestation_id, "attestation")?;

            if attestation.unsigned.kind != EventType::AttestationIssued {
                return Err(invalid_event(format!(
                    "attestation.revoked references {} event {}",
                    attestation.unsigned.kind, attestation.id
                )));
            }

            if attestation.unsigned.subject != event.unsigned.subject {
                return Err(invalid_event(
                    "attestation.revoked subject must match referenced attestation subject",
                ));
            }

            if attestation.unsigned.issuer != event.unsigned.issuer {
                return Err(invalid_event(
                    "attestation.revoked issuer must match referenced attestation issuer",
                ));
            }
        }
        EventType::IdentityCreated | EventType::ClaimAdded | EventType::AttestationIssued => {}
    }

    Ok(())
}

pub fn query_events(
    store: &impl EventStore,
    filter: &EventFilter,
) -> Result<Vec<SignedEvent>, UseCaseError> {
    Ok(store.query(filter)?)
}

pub fn active_claims(
    store: &impl EventStore,
    subject: impl Into<String>,
) -> Result<Vec<SignedEvent>, UseCaseError> {
    let events = store.query(&EventFilter {
        subject: Some(subject.into()),
        limit: Some(i64::MAX as usize),
        ..EventFilter::default()
    })?;

    Ok(active_events(
        &events,
        EventType::ClaimAdded,
        EventType::ClaimRevoked,
        "claim_id",
    ))
}

pub fn active_attestations(
    store: &impl EventStore,
    subject: impl Into<String>,
) -> Result<Vec<SignedEvent>, UseCaseError> {
    let events = store.query(&EventFilter {
        subject: Some(subject.into()),
        limit: Some(i64::MAX as usize),
        ..EventFilter::default()
    })?;

    Ok(active_events(
        &events,
        EventType::AttestationIssued,
        EventType::AttestationRevoked,
        "attestation_id",
    ))
}

fn active_events(
    events: &[SignedEvent],
    active_kind: EventType,
    revoked_kind: EventType,
    reference_field: &str,
) -> Vec<SignedEvent> {
    let revoked_ids = events
        .iter()
        .filter(|event| event.unsigned.kind == revoked_kind)
        .filter_map(|event| payload_string(event, reference_field).ok())
        .collect::<HashSet<_>>();

    events
        .iter()
        .filter(|event| event.unsigned.kind == active_kind)
        .filter(|event| !revoked_ids.contains(event.id.as_str()))
        .cloned()
        .collect()
}

fn event_already_stored(
    store: &impl EventStore,
    event: &SignedEvent,
) -> Result<bool, UseCaseError> {
    let Some(existing) = store.get(&event.id)? else {
        return Ok(false);
    };

    if existing == *event {
        Ok(true)
    } else {
        Err(invalid_event(format!(
            "event id conflict: stored event {} differs from submitted event",
            event.id
        )))
    }
}

fn require_referenced_event(
    store: &impl EventStore,
    id: &str,
    label: &str,
) -> Result<SignedEvent, UseCaseError> {
    store
        .get(id)?
        .ok_or_else(|| invalid_event(format!("referenced {label} event not found: {id}")))
}

fn payload_string<'a>(event: &'a SignedEvent, field: &str) -> Result<&'a str, UseCaseError> {
    event
        .unsigned
        .payload
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| invalid_event(format!("payload.{field} must be a non-empty string")))
}

fn invalid_event(message: impl Into<String>) -> UseCaseError {
    UseCaseError::Domain(DomainError::InvalidEvent(message.into()))
}

fn is_missing_reference_error(error: &UseCaseError) -> bool {
    matches!(
        error,
        UseCaseError::Domain(DomainError::InvalidEvent(message))
            if message.starts_with("referenced ") && message.contains(" event not found:")
    )
}

fn accepted_result(event: &SignedEvent) -> BatchSubmitResult {
    BatchSubmitResult {
        id: Some(event.id.clone()),
        accepted: true,
        error: None,
    }
}

fn rejected_result(event: &SignedEvent, error: UseCaseError) -> BatchSubmitResult {
    BatchSubmitResult {
        id: Some(event.id.clone()),
        accepted: false,
        error: Some(error.to_string()),
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SyncSummary {
    pub pulled: usize,
    pub accepted: usize,
    pub rejected: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyncFromPeerOptions {
    pub page_limit: usize,
    pub from_beginning: bool,
}

pub fn sync_from_peer(
    peer: &impl PeerEventClient,
    store: &impl EventStore,
    verifier: &impl Verifier,
    page_limit: usize,
) -> Result<SyncSummary, UseCaseError> {
    let page_limit = page_limit.max(1);
    let mut filter = EventFilter {
        limit: Some(page_limit),
        ..EventFilter::default()
    };
    let mut summary = SyncSummary::default();
    let mut pending_references = Vec::new();

    loop {
        let events = peer.list_events(&filter)?;
        if events.is_empty() {
            break;
        }

        apply_synced_events(
            store,
            verifier,
            &events,
            &mut summary,
            &mut pending_references,
        );

        let last = events.last().expect("events is not empty");
        filter.after_created_at = Some(last.unsigned.created_at);
        filter.after_id = Some(last.id.clone());

        if events.len() < page_limit {
            break;
        }
    }

    reject_pending_synced_events(&mut summary, &pending_references);
    Ok(summary)
}

pub fn sync_from_peer_with_state(
    peer_url: &str,
    peer: &impl PeerEventClient,
    store: &impl EventStore,
    state_store: &impl PeerSyncStateStore,
    verifier: &impl Verifier,
    clock: &impl Clock,
    options: SyncFromPeerOptions,
) -> Result<SyncSummary, UseCaseError> {
    let mut filter = EventFilter::default();

    if !options.from_beginning {
        if let Some(state) = state_store.get_peer_sync_state(peer_url)? {
            filter.after_created_at = Some(state.last_created_at);
            filter.after_id = Some(state.last_id);
        }
    }

    let page_limit = options.page_limit.max(1);
    filter.limit = Some(page_limit);
    let mut summary = SyncSummary::default();
    let mut pending_references = Vec::new();

    loop {
        let events = peer.list_events(&filter)?;
        if events.is_empty() {
            break;
        }

        apply_synced_events(
            store,
            verifier,
            &events,
            &mut summary,
            &mut pending_references,
        );

        let last = events.last().expect("events is not empty");
        filter.after_created_at = Some(last.unsigned.created_at);
        filter.after_id = Some(last.id.clone());
        state_store.put_peer_sync_state(&PeerSyncState {
            peer_url: peer_url.to_string(),
            last_created_at: last.unsigned.created_at,
            last_id: last.id.clone(),
            updated_at: clock.now_unix_seconds(),
        })?;

        if events.len() < page_limit {
            break;
        }
    }

    reject_pending_synced_events(&mut summary, &pending_references);
    Ok(summary)
}

fn apply_synced_events(
    store: &impl EventStore,
    verifier: &impl Verifier,
    events: &[SignedEvent],
    summary: &mut SyncSummary,
    pending_references: &mut Vec<SignedEvent>,
) {
    summary.pulled += events.len();
    pending_references.extend_from_slice(events);

    let batch = submit_events_with_reference_retry(store, verifier, pending_references);
    let mut still_pending = Vec::new();

    for (event, result) in pending_references.iter().zip(batch.results) {
        if result.accepted {
            summary.accepted += 1;
        } else if result
            .error
            .as_deref()
            .map(is_missing_reference_message)
            .unwrap_or(false)
        {
            still_pending.push(event.clone());
        } else {
            summary.rejected += 1;
        }
    }

    *pending_references = still_pending;
}

fn reject_pending_synced_events(summary: &mut SyncSummary, pending_references: &[SignedEvent]) {
    summary.rejected += pending_references.len();
}

fn is_missing_reference_message(message: &str) -> bool {
    message.starts_with("invalid event: referenced ") && message.contains(" event not found:")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{Ed25519Keypair, Ed25519Verifier};
    use crate::ports::{Clock, EventStore, PeerError, PeerEventClient, PeerSyncStateStore};
    use crate::testing::InMemoryEventStore;

    struct FixedClock;

    struct TimeClock(i64);

    struct StaticPeer {
        events: Vec<SignedEvent>,
    }

    impl PeerEventClient for StaticPeer {
        fn list_events(&self, filter: &EventFilter) -> Result<Vec<SignedEvent>, PeerError> {
            let store = InMemoryEventStore::new();
            for event in &self.events {
                store.append(event).unwrap();
            }
            store
                .query(filter)
                .map_err(|err| PeerError::Failure(err.to_string()))
        }
    }

    impl Clock for FixedClock {
        fn now_unix_seconds(&self) -> i64 {
            1_700_000_000
        }
    }

    impl Clock for TimeClock {
        fn now_unix_seconds(&self) -> i64 {
            self.0
        }
    }

    #[test]
    fn creates_and_verifies_identity_event() {
        let keypair = Ed25519Keypair::generate();
        let event = create_identity(&FixedClock, &keypair).unwrap();

        assert_eq!(event.unsigned.subject, keypair.public_key());
        verify_event(&event, &Ed25519Verifier).unwrap();
    }

    #[test]
    fn detects_tampered_event() {
        let keypair = Ed25519Keypair::generate();
        let mut event = add_claim(&FixedClock, &keypair, "github", "joris", None).unwrap();
        event.unsigned.payload["value"] = Value::String("mallory".into());

        assert!(verify_event(&event, &Ed25519Verifier).is_err());
    }

    #[test]
    fn submits_and_queries_events_with_in_memory_store() {
        let keypair = Ed25519Keypair::generate();
        let store = InMemoryEventStore::new();
        let identity = create_identity(&FixedClock, &keypair).unwrap();
        let claim = add_claim(&FixedClock, &keypair, "github", "joris", None).unwrap();

        submit_event(&store, &Ed25519Verifier, &identity).unwrap();
        submit_event(&store, &Ed25519Verifier, &claim).unwrap();
        submit_event(&store, &Ed25519Verifier, &claim).unwrap();

        let events = query_events(
            &store,
            &EventFilter {
                subject: Some(keypair.public_key()),
                ..EventFilter::default()
            },
        )
        .unwrap();

        assert_eq!(events.len(), 2);
        assert!(events
            .iter()
            .any(|event| event.unsigned.kind == EventType::IdentityCreated));
        assert!(events
            .iter()
            .any(|event| event.unsigned.kind == EventType::ClaimAdded));
    }

    #[test]
    fn active_claims_exclude_revoked_claims() {
        let signer = Ed25519Keypair::generate();
        let store = InMemoryEventStore::new();
        let active = add_claim(&FixedClock, &signer, "github", "joris", None).unwrap();
        let revoked = add_claim(&FixedClock, &signer, "domain", "example.com", None).unwrap();
        submit_event(&store, &Ed25519Verifier, &active).unwrap();
        submit_event(&store, &Ed25519Verifier, &revoked).unwrap();
        let revocation = revoke_claim(&FixedClock, &signer, &revoked.id).unwrap();
        submit_event(&store, &Ed25519Verifier, &revocation).unwrap();

        let claims = active_claims(&store, signer.public_key()).unwrap();

        assert_eq!(claims.len(), 1);
        assert_eq!(claims[0].id, active.id);
    }

    #[test]
    fn active_attestations_exclude_revoked_attestations() {
        let issuer = Ed25519Keypair::generate();
        let subject = Ed25519Keypair::generate();
        let store = InMemoryEventStore::new();
        let active = issue_attestation(
            &FixedClock,
            &issuer,
            subject.public_key(),
            "maintainer",
            None,
        )
        .unwrap();
        let revoked =
            issue_attestation(&FixedClock, &issuer, subject.public_key(), "reviewer", None)
                .unwrap();
        submit_event(&store, &Ed25519Verifier, &active).unwrap();
        submit_event(&store, &Ed25519Verifier, &revoked).unwrap();
        let revocation =
            revoke_attestation(&FixedClock, &issuer, subject.public_key(), &revoked.id).unwrap();
        submit_event(&store, &Ed25519Verifier, &revocation).unwrap();

        let attestations = active_attestations(&store, subject.public_key()).unwrap();

        assert_eq!(attestations.len(), 1);
        assert_eq!(attestations[0].id, active.id);
    }

    #[test]
    fn validate_event_for_submission_does_not_append_event() {
        let keypair = Ed25519Keypair::generate();
        let store = InMemoryEventStore::new();
        let event = create_identity(&FixedClock, &keypair).unwrap();

        validate_event_for_submission(&store, &Ed25519Verifier, &event).unwrap();

        assert!(store.get(&event.id).unwrap().is_none());
    }

    #[test]
    fn submit_event_rejects_same_id_with_different_content() {
        let keypair = Ed25519Keypair::generate();
        let store = InMemoryEventStore::new();
        let event = create_identity(&FixedClock, &keypair).unwrap();
        let mut conflicting = event.clone();
        conflicting.signature = "different-signature".to_string();
        store.append(&conflicting).unwrap();

        let error = submit_event(&store, &Ed25519Verifier, &event).unwrap_err();
        assert!(error.to_string().contains("event id conflict"));
    }

    #[test]
    fn submit_events_with_reference_retry_accepts_out_of_order_revocation() {
        let keypair = Ed25519Keypair::generate();
        let store = InMemoryEventStore::new();
        let claim = add_claim(&FixedClock, &keypair, "github", "joris", None).unwrap();
        let revocation = revoke_claim(&FixedClock, &keypair, &claim.id).unwrap();

        let summary = submit_events_with_reference_retry(
            &store,
            &Ed25519Verifier,
            &[revocation.clone(), claim.clone()],
        );

        assert_eq!(summary.accepted, 2);
        assert_eq!(summary.rejected, 0);
        assert!(store.get(&claim.id).unwrap().is_some());
        assert!(store.get(&revocation.id).unwrap().is_some());
        assert!(active_claims(&store, keypair.public_key())
            .unwrap()
            .is_empty());
    }

    #[test]
    fn sync_from_peer_pulls_pages_into_store() {
        let keypair = Ed25519Keypair::generate();
        let identity = create_identity(&FixedClock, &keypair).unwrap();
        let claim = add_claim(&FixedClock, &keypair, "github", "joris", None).unwrap();
        let peer = StaticPeer {
            events: vec![identity, claim],
        };
        let store = InMemoryEventStore::new();

        let summary = sync_from_peer(&peer, &store, &Ed25519Verifier, 1).unwrap();

        assert_eq!(summary.pulled, 2);
        assert_eq!(summary.accepted, 2);
        assert_eq!(summary.rejected, 0);
        assert_eq!(store.query(&EventFilter::default()).unwrap().len(), 2);
    }

    #[test]
    fn sync_from_peer_retries_out_of_order_revocation_across_pages() {
        let keypair = Ed25519Keypair::generate();
        let claim =
            add_claim(&TimeClock(1_700_000_001), &keypair, "github", "joris", None).unwrap();
        let revocation = revoke_claim(&TimeClock(1_700_000_000), &keypair, &claim.id).unwrap();
        let peer = StaticPeer {
            events: vec![revocation.clone(), claim.clone()],
        };
        let store = InMemoryEventStore::new();

        let summary = sync_from_peer(&peer, &store, &Ed25519Verifier, 1).unwrap();

        assert_eq!(summary.pulled, 2);
        assert_eq!(summary.accepted, 2);
        assert_eq!(summary.rejected, 0);
        assert!(store.get(&claim.id).unwrap().is_some());
        assert!(store.get(&revocation.id).unwrap().is_some());
        assert!(active_claims(&store, keypair.public_key())
            .unwrap()
            .is_empty());
    }

    #[test]
    fn sync_from_peer_with_state_resumes_from_last_cursor() {
        let keypair = Ed25519Keypair::generate();
        let identity = create_identity(&FixedClock, &keypair).unwrap();
        let claim = add_claim(&FixedClock, &keypair, "github", "joris", None).unwrap();
        let store = InMemoryEventStore::new();
        let state_store = InMemoryEventStore::new();
        let peer = StaticPeer {
            events: vec![identity.clone(), claim.clone()],
        };

        let options = SyncFromPeerOptions {
            page_limit: 1,
            from_beginning: false,
        };
        let first = sync_from_peer_with_state(
            "peer-a",
            &peer,
            &store,
            &state_store,
            &Ed25519Verifier,
            &FixedClock,
            options,
        )
        .unwrap();
        let second = sync_from_peer_with_state(
            "peer-a",
            &peer,
            &store,
            &state_store,
            &Ed25519Verifier,
            &FixedClock,
            options,
        )
        .unwrap();

        assert_eq!(first.pulled, 2);
        assert_eq!(first.accepted, 2);
        assert_eq!(second.pulled, 0);
        assert!(state_store.get_peer_sync_state("peer-a").unwrap().is_some());
    }

    #[test]
    fn creates_revocation_events() {
        let issuer = Ed25519Keypair::generate();
        let subject = Ed25519Keypair::generate();
        let claim = add_claim(&FixedClock, &issuer, "github", "joris", None).unwrap();
        let claim_revocation = revoke_claim(&FixedClock, &issuer, &claim.id).unwrap();

        assert_eq!(claim_revocation.unsigned.kind, EventType::ClaimRevoked);
        assert_eq!(claim_revocation.unsigned.payload["claim_id"], claim.id);
        verify_event(&claim_revocation, &Ed25519Verifier).unwrap();

        let attestation = issue_attestation(
            &FixedClock,
            &issuer,
            subject.public_key(),
            "trusted_contributor",
            None,
        )
        .unwrap();
        let attestation_revocation =
            revoke_attestation(&FixedClock, &issuer, subject.public_key(), &attestation.id)
                .unwrap();

        assert_eq!(
            attestation_revocation.unsigned.kind,
            EventType::AttestationRevoked
        );
        assert_eq!(
            attestation_revocation.unsigned.payload["attestation_id"],
            attestation.id
        );
        verify_event(&attestation_revocation, &Ed25519Verifier).unwrap();
    }

    #[test]
    fn submit_claim_revocation_requires_existing_matching_claim() {
        let issuer = Ed25519Keypair::generate();
        let other = Ed25519Keypair::generate();
        let store = InMemoryEventStore::new();
        let claim = add_claim(&FixedClock, &issuer, "github", "joris", None).unwrap();
        let revocation = revoke_claim(&FixedClock, &issuer, &claim.id).unwrap();

        let missing = submit_event(&store, &Ed25519Verifier, &revocation).unwrap_err();
        assert!(missing
            .to_string()
            .contains("referenced claim event not found"));

        submit_event(&store, &Ed25519Verifier, &claim).unwrap();
        submit_event(&store, &Ed25519Verifier, &revocation).unwrap();

        let wrong_issuer_revocation = sign_event(
            &other,
            UnsignedEvent::new(
                EventType::ClaimRevoked,
                issuer.public_key(),
                other.public_key(),
                FixedClock.now_unix_seconds(),
                json!({ "claim_id": claim.id }),
            ),
        )
        .unwrap();
        let wrong_issuer =
            submit_event(&store, &Ed25519Verifier, &wrong_issuer_revocation).unwrap_err();
        assert!(wrong_issuer
            .to_string()
            .contains("claim.revoked issuer must match"));
    }

    #[test]
    fn submit_claim_revocation_rejects_wrong_reference_type_or_subject() {
        let issuer = Ed25519Keypair::generate();
        let other_subject = Ed25519Keypair::generate();
        let store = InMemoryEventStore::new();
        let identity = create_identity(&FixedClock, &issuer).unwrap();
        let claim = add_claim(&FixedClock, &issuer, "github", "joris", None).unwrap();
        submit_event(&store, &Ed25519Verifier, &identity).unwrap();
        submit_event(&store, &Ed25519Verifier, &claim).unwrap();

        let wrong_type = revoke_claim(&FixedClock, &issuer, &identity.id).unwrap();
        let wrong_type_error = submit_event(&store, &Ed25519Verifier, &wrong_type).unwrap_err();
        assert!(wrong_type_error
            .to_string()
            .contains("claim.revoked references identity.created"));

        let wrong_subject = sign_event(
            &issuer,
            UnsignedEvent::new(
                EventType::ClaimRevoked,
                other_subject.public_key(),
                issuer.public_key(),
                FixedClock.now_unix_seconds(),
                json!({ "claim_id": claim.id }),
            ),
        )
        .unwrap();
        let wrong_subject_error =
            submit_event(&store, &Ed25519Verifier, &wrong_subject).unwrap_err();
        assert!(wrong_subject_error
            .to_string()
            .contains("claim.revoked subject must match"));
    }

    #[test]
    fn submit_attestation_revocation_requires_existing_matching_attestation() {
        let issuer = Ed25519Keypair::generate();
        let other_issuer = Ed25519Keypair::generate();
        let subject = Ed25519Keypair::generate();
        let other_subject = Ed25519Keypair::generate();
        let store = InMemoryEventStore::new();
        let attestation = issue_attestation(
            &FixedClock,
            &issuer,
            subject.public_key(),
            "trusted_contributor",
            None,
        )
        .unwrap();
        let revocation =
            revoke_attestation(&FixedClock, &issuer, subject.public_key(), &attestation.id)
                .unwrap();

        let missing = submit_event(&store, &Ed25519Verifier, &revocation).unwrap_err();
        assert!(missing
            .to_string()
            .contains("referenced attestation event not found"));

        submit_event(&store, &Ed25519Verifier, &attestation).unwrap();
        submit_event(&store, &Ed25519Verifier, &revocation).unwrap();

        let wrong_subject = revoke_attestation(
            &FixedClock,
            &issuer,
            other_subject.public_key(),
            &attestation.id,
        )
        .unwrap();
        let wrong_subject_error =
            submit_event(&store, &Ed25519Verifier, &wrong_subject).unwrap_err();
        assert!(wrong_subject_error
            .to_string()
            .contains("attestation.revoked subject must match"));

        let wrong_issuer = revoke_attestation(
            &FixedClock,
            &other_issuer,
            subject.public_key(),
            &attestation.id,
        )
        .unwrap();
        let wrong_issuer_error = submit_event(&store, &Ed25519Verifier, &wrong_issuer).unwrap_err();
        assert!(wrong_issuer_error
            .to_string()
            .contains("attestation.revoked issuer must match"));
    }

    #[test]
    fn submit_attestation_revocation_rejects_wrong_reference_type() {
        let issuer = Ed25519Keypair::generate();
        let store = InMemoryEventStore::new();
        let claim = add_claim(&FixedClock, &issuer, "github", "joris", None).unwrap();
        submit_event(&store, &Ed25519Verifier, &claim).unwrap();

        let wrong_type =
            revoke_attestation(&FixedClock, &issuer, issuer.public_key(), &claim.id).unwrap();
        let error = submit_event(&store, &Ed25519Verifier, &wrong_type).unwrap_err();
        assert!(error
            .to_string()
            .contains("attestation.revoked references claim.added"));
    }
}
