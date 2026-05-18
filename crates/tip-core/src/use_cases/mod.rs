use serde_json::{json, Value};

use crate::{
    domain::{DomainError, EventFilter, EventType, SignedEvent, UnsignedEvent},
    ports::{
        Clock, CryptoError, EventStore, PeerError, PeerEventClient, Signer, StoreError, Verifier,
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
    verify_event(event, verifier)?;
    store.append(event)?;
    Ok(())
}

pub fn query_events(
    store: &impl EventStore,
    filter: &EventFilter,
) -> Result<Vec<SignedEvent>, UseCaseError> {
    Ok(store.query(filter)?)
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SyncSummary {
    pub pulled: usize,
    pub accepted: usize,
    pub rejected: usize,
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

    loop {
        let events = peer.list_events(&filter)?;
        if events.is_empty() {
            break;
        }

        summary.pulled += events.len();

        for event in &events {
            match submit_event(store, verifier, event) {
                Ok(()) => summary.accepted += 1,
                Err(_) => summary.rejected += 1,
            }
        }

        let last = events.last().expect("events is not empty");
        filter.after_created_at = Some(last.unsigned.created_at);
        filter.after_id = Some(last.id.clone());

        if events.len() < page_limit {
            break;
        }
    }

    Ok(summary)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{Ed25519Keypair, Ed25519Verifier};
    use crate::ports::{Clock, EventStore, PeerError, PeerEventClient};
    use crate::testing::InMemoryEventStore;

    struct FixedClock;

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
}
