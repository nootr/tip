use serde_json::json;
use tip_core::{
    crypto::Ed25519Keypair,
    ports::{Clock, Signer},
    use_cases::{add_claim, create_identity, issue_attestation, revoke_attestation, revoke_claim},
};

struct VectorClock;

impl Clock for VectorClock {
    fn now_unix_seconds(&self) -> i64 {
        1_700_000_000
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let issuer = Ed25519Keypair::from_seed_base64("AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE")?;
    let subject = Ed25519Keypair::from_seed_base64("AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI")?;

    let identity = create_identity(&VectorClock, &issuer)?;
    let claim = add_claim(
        &VectorClock,
        &issuer,
        "github",
        "joris",
        Some(json!({ "url": "https://gist.github.com/joris/tip-proof" })),
    )?;
    let claim_revocation = revoke_claim(&VectorClock, &issuer, &claim.id)?;
    let attestation = issue_attestation(
        &VectorClock,
        &issuer,
        subject.public_key(),
        "trusted_contributor",
        Some("Useful open-source contributor".to_string()),
    )?;
    let attestation_revocation =
        revoke_attestation(&VectorClock, &issuer, subject.public_key(), &attestation.id)?;

    let output = json!({
        "description": "TIP 0.1 deterministic Ed25519/JCS test vectors",
        "issuer_seed": issuer.seed_base64(),
        "issuer_public_key": issuer.public_key(),
        "subject_seed": subject.seed_base64(),
        "subject_public_key": subject.public_key(),
        "events": {
            "identity_created": identity,
            "claim_added": claim,
            "claim_revoked": claim_revocation,
            "attestation_issued": attestation,
            "attestation_revoked": attestation_revocation,
        }
    });

    println!("{}", serde_json::to_string_pretty(&output)?);
    Ok(())
}
