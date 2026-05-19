use serde::Deserialize;
use std::collections::{BTreeMap, HashSet};
use tip_core::{crypto::Ed25519Verifier, use_cases, EventType, SignedEvent};

#[derive(Deserialize)]
struct TestVectors {
    events: BTreeMap<String, SignedEvent>,
}

#[derive(Deserialize)]
struct BundleVector {
    bundle: TestBundle,
}

#[derive(Deserialize)]
struct TestBundle {
    version: String,
    subject: String,
    events: Vec<SignedEvent>,
    active_claims: Vec<SignedEvent>,
    active_attestations: Vec<SignedEvent>,
}

#[test]
fn tip_0_1_test_vectors_verify() {
    let vectors: TestVectors =
        serde_json::from_str(include_str!("../../../test-vectors/tip-0.1.json")).unwrap();

    assert_eq!(vectors.events.len(), 5);
    for event in vectors.events.values() {
        use_cases::verify_event(event, &Ed25519Verifier).unwrap();
        assert_eq!(event.unsigned.event_id().unwrap(), event.id);
    }
}

#[test]
fn tip_bundle_0_1_test_vector_verifies() {
    let vector: BundleVector =
        serde_json::from_str(include_str!("../../../test-vectors/tip-bundle-0.1.json")).unwrap();
    let bundle = vector.bundle;

    assert_eq!(bundle.version, "tip-bundle/0.1");
    assert_eq!(bundle.events.len(), 3);

    for event in &bundle.events {
        assert_eq!(event.unsigned.subject, bundle.subject);
        use_cases::verify_event(event, &Ed25519Verifier).unwrap();
    }

    assert!(bundle
        .active_claims
        .iter()
        .chain(bundle.active_attestations.iter())
        .all(|projected| bundle.events.iter().any(|event| event == projected)));

    assert_eq!(
        event_ids(&bundle.active_claims),
        event_ids(&active_events(
            &bundle.events,
            EventType::ClaimAdded,
            EventType::ClaimRevoked,
            "claim_id",
        ))
    );
    assert_eq!(
        event_ids(&bundle.active_attestations),
        event_ids(&active_events(
            &bundle.events,
            EventType::AttestationIssued,
            EventType::AttestationRevoked,
            "attestation_id",
        ))
    );
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
        .filter_map(|event| {
            event
                .unsigned
                .payload
                .get(reference_field)
                .and_then(serde_json::Value::as_str)
        })
        .collect::<HashSet<_>>();

    events
        .iter()
        .filter(|event| event.unsigned.kind == active_kind)
        .filter(|event| !revoked_ids.contains(event.id.as_str()))
        .cloned()
        .collect()
}

fn event_ids(events: &[SignedEvent]) -> HashSet<&str> {
    events.iter().map(|event| event.id.as_str()).collect()
}
