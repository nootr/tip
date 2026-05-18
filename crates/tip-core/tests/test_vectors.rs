use serde::Deserialize;
use std::collections::BTreeMap;
use tip_core::{crypto::Ed25519Verifier, use_cases, SignedEvent};

#[derive(Deserialize)]
struct TestVectors {
    events: BTreeMap<String, SignedEvent>,
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
