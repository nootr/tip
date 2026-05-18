use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{fmt, str::FromStr};

pub const PROTOCOL_VERSION: &str = "tip/0.1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EventType {
    #[serde(rename = "identity.created")]
    IdentityCreated,
    #[serde(rename = "claim.added")]
    ClaimAdded,
    #[serde(rename = "claim.revoked")]
    ClaimRevoked,
    #[serde(rename = "attestation.issued")]
    AttestationIssued,
    #[serde(rename = "attestation.revoked")]
    AttestationRevoked,
}

impl fmt::Display for EventType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            EventType::IdentityCreated => "identity.created",
            EventType::ClaimAdded => "claim.added",
            EventType::ClaimRevoked => "claim.revoked",
            EventType::AttestationIssued => "attestation.issued",
            EventType::AttestationRevoked => "attestation.revoked",
        })
    }
}

impl FromStr for EventType {
    type Err = DomainError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "identity.created" => Ok(EventType::IdentityCreated),
            "claim.added" => Ok(EventType::ClaimAdded),
            "claim.revoked" => Ok(EventType::ClaimRevoked),
            "attestation.issued" => Ok(EventType::AttestationIssued),
            "attestation.revoked" => Ok(EventType::AttestationRevoked),
            other => Err(DomainError::UnknownEventType(other.to_string())),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnsignedEvent {
    pub version: String,
    #[serde(rename = "type")]
    pub kind: EventType,
    pub subject: String,
    pub issuer: String,
    pub created_at: i64,
    pub payload: Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedEvent {
    pub id: String,
    #[serde(flatten)]
    pub unsigned: UnsignedEvent,
    pub signature: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EventFilter {
    pub subject: Option<String>,
    pub issuer: Option<String>,
    pub kind: Option<EventType>,
    pub after_created_at: Option<i64>,
    pub after_id: Option<String>,
    pub limit: Option<usize>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum DomainError {
    #[error("failed to serialize canonical event: {0}")]
    CanonicalSerialization(String),
    #[error("unknown event type: {0}")]
    UnknownEventType(String),
    #[error("invalid event: {0}")]
    InvalidEvent(String),
}

impl UnsignedEvent {
    pub fn new(
        kind: EventType,
        subject: String,
        issuer: String,
        created_at: i64,
        payload: Value,
    ) -> Self {
        Self {
            version: PROTOCOL_VERSION.to_string(),
            kind,
            subject,
            issuer,
            created_at,
            payload,
        }
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, DomainError> {
        serde_json_canonicalizer::to_vec(self)
            .map_err(|err| DomainError::CanonicalSerialization(err.to_string()))
    }

    pub fn event_id(&self) -> Result<String, DomainError> {
        let bytes = self.canonical_bytes()?;
        let digest = Sha256::digest(bytes);
        Ok(format!("sha256:{}", hex::encode(digest)))
    }

    pub fn validate_shape(&self) -> Result<(), DomainError> {
        if self.version != PROTOCOL_VERSION {
            return Err(DomainError::InvalidEvent(format!(
                "unsupported protocol version {}",
                self.version
            )));
        }

        if self.subject.is_empty() {
            return Err(DomainError::InvalidEvent("subject is required".into()));
        }

        if self.issuer.is_empty() {
            return Err(DomainError::InvalidEvent("issuer is required".into()));
        }

        reject_floating_point_numbers(&self.payload)?;

        match self.kind {
            EventType::IdentityCreated => {
                if self.subject != self.issuer {
                    return Err(DomainError::InvalidEvent(
                        "identity.created subject must equal issuer".into(),
                    ));
                }
            }
            EventType::ClaimAdded => {
                require_string(&self.payload, "claim_type")?;
                require_string(&self.payload, "value")?;
            }
            EventType::ClaimRevoked => {
                require_string(&self.payload, "claim_id")?;
            }
            EventType::AttestationIssued => {
                require_string(&self.payload, "claim")?;
            }
            EventType::AttestationRevoked => {
                require_string(&self.payload, "attestation_id")?;
            }
        }

        Ok(())
    }
}

impl SignedEvent {
    pub fn validate_id_and_shape(&self) -> Result<(), DomainError> {
        self.unsigned.validate_shape()?;
        let expected_id = self.unsigned.event_id()?;
        if self.id != expected_id {
            return Err(DomainError::InvalidEvent(format!(
                "event id mismatch: expected {}, got {}",
                expected_id, self.id
            )));
        }
        Ok(())
    }
}

fn require_string(payload: &Value, field: &str) -> Result<(), DomainError> {
    match payload.get(field).and_then(Value::as_str) {
        Some(value) if !value.is_empty() => Ok(()),
        _ => Err(DomainError::InvalidEvent(format!(
            "payload.{} must be a non-empty string",
            field
        ))),
    }
}

fn reject_floating_point_numbers(value: &Value) -> Result<(), DomainError> {
    match value {
        Value::Number(number) if !(number.is_i64() || number.is_u64()) => {
            Err(DomainError::InvalidEvent(
                "floating point numbers are not allowed in TIP 0.1 events".into(),
            ))
        }
        Value::Array(values) => values.iter().try_for_each(reject_floating_point_numbers),
        Value::Object(map) => map.values().try_for_each(reject_floating_point_numbers),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn event_id_is_stable_for_same_unsigned_event() {
        let event = UnsignedEvent::new(
            EventType::ClaimAdded,
            "subject".into(),
            "issuer".into(),
            1,
            json!({"claim_type":"github","value":"joris"}),
        );

        assert_eq!(event.event_id().unwrap(), event.event_id().unwrap());
        assert!(event.event_id().unwrap().starts_with("sha256:"));
    }

    #[test]
    fn canonical_bytes_follow_jcs_key_ordering() {
        let event = UnsignedEvent::new(
            EventType::ClaimAdded,
            "subject".into(),
            "issuer".into(),
            1_700_000_000,
            json!({"value":"joris","claim_type":"github"}),
        );

        let canonical = String::from_utf8(event.canonical_bytes().unwrap()).unwrap();

        assert_eq!(
            canonical,
            r#"{"created_at":1700000000,"issuer":"issuer","payload":{"claim_type":"github","value":"joris"},"subject":"subject","type":"claim.added","version":"tip/0.1"}"#
        );
        assert_eq!(
            event.event_id().unwrap(),
            "sha256:eae7ad214858140654512bcb30ee6162f91a8bc581f10e6a61cda4f0b9d0a8af"
        );
    }

    #[test]
    fn floating_point_payload_numbers_are_rejected() {
        let event = UnsignedEvent::new(
            EventType::ClaimAdded,
            "subject".into(),
            "issuer".into(),
            1,
            json!({"claim_type":"score","value":"demo","weight":1.25}),
        );

        assert!(event.validate_shape().is_err());
    }
}
