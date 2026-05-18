# TIP 0.1 — Trust Infrastructure Protocol

TIP is a portable cryptographic trust evidence protocol. It is not a global reputation score, a social network, or a blockchain.

## Goals

- Users and agents are represented by cryptographic public keys.
- Claims and attestations are signed events.
- Nodes store and serve valid public events.
- Clients decide which issuers and signals they trust.

## Non-goals for 0.1

- Global scoring.
- Blockchain dependency.
- Private or selective disclosure events.
- Peer discovery or federation sync.
- External proof verification by nodes.

## Identity model

The canonical identity is an Ed25519 public key encoded as base64url without padding. Handles, GitHub usernames, domains, and other names are claims, not canonical identities.

## Event model

TIP 0.1 is event-sourced. Current state is reconstructed from signed append-only events.

A signed event contains:

```json
{
  "id": "sha256:<hex>",
  "version": "tip/0.1",
  "type": "claim.added",
  "subject": "<subject-public-key>",
  "issuer": "<issuer-public-key>",
  "created_at": 1700000000,
  "payload": {},
  "signature": "<base64url-ed25519-signature>"
}
```

`id` is `sha256:` plus the lowercase hex SHA-256 digest of the canonical unsigned event JSON. The signature is Ed25519 over the same canonical unsigned event JSON bytes.

The unsigned event fields are:

- `version`
- `type`
- `subject`
- `issuer`
- `created_at`
- `payload`

## Canonical JSON in 0.1

TIP 0.1 uses the JSON Canonicalization Scheme (JCS), RFC 8785.

Rules:

- canonicalize the unsigned event object with JCS
- sign exactly those canonical UTF-8 bytes
- hash exactly those canonical UTF-8 bytes
- floating point numbers are not allowed in TIP 0.1 events

Example unsigned event:

```json
{
  "version": "tip/0.1",
  "type": "claim.added",
  "subject": "subject",
  "issuer": "issuer",
  "created_at": 1700000000,
  "payload": {
    "value": "joris",
    "claim_type": "github"
  }
}
```

JCS canonical bytes as UTF-8 text:

```json
{"created_at":1700000000,"issuer":"issuer","payload":{"claim_type":"github","value":"joris"},"subject":"subject","type":"claim.added","version":"tip/0.1"}
```

Expected event id:

```text
sha256:eae7ad214858140654512bcb30ee6162f91a8bc581f10e6a61cda4f0b9d0a8af
```

## Event types

### `identity.created`

Declares an identity key.

Rules:

- `subject == issuer`
- payload is `{}`

### `claim.added`

Adds a public claim about the subject.

Required payload fields:

```json
{
  "claim_type": "github",
  "value": "joris",
  "proof": { "url": "https://gist.github.com/..." }
}
```

Nodes do not verify external proofs.

### `claim.revoked`

Revokes a previous claim.

Required payload fields:

```json
{
  "claim_id": "sha256:<event-id>"
}
```

### `attestation.issued`

Issuer signs a statement about subject.

Required payload fields:

```json
{
  "claim": "trusted_contributor",
  "message": "optional context"
}
```

Anyone may issue attestations. Clients decide what counts.

### `attestation.revoked`

Revokes a previous attestation from the same issuer.

Required payload fields:

```json
{
  "attestation_id": "sha256:<event-id>"
}
```

## Node validation

On `POST /events`, nodes MUST validate:

- event shape and required fields
- supported protocol version
- known event type
- event id matches canonical unsigned event hash
- Ed25519 signature verifies against `issuer`

Nodes MUST NOT treat external claims as true merely because the event is valid.

## HTTP API

- `GET /health`
- `GET /info`
- `POST /events`
- `POST /events/batch`
- `GET /events/{id}`
- `GET /events?subject=...&issuer=...&type=...`
- `GET /identities/{pubkey}/events`

### Batch event submission

`POST /events/batch` accepts a JSON array of signed events and returns per-event results:

```json
{
  "accepted": 1,
  "rejected": 1,
  "results": [
    { "id": "sha256:...", "accepted": true, "error": null },
    { "id": "sha256:...", "accepted": false, "error": "event id mismatch" }
  ]
}
```

Batch submission is idempotent: submitting an already stored valid event is still accepted and does not create a duplicate.

## Privacy and safety

TIP 0.1 is a public event layer. Publishing an event to a node makes it public. Revocation can add new evidence, but cannot erase already replicated data.
