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
- Peer discovery, consensus, or global replication guarantees.
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

Rules:

- `claim_id` MUST reference an existing `claim.added` event
- `subject` MUST match the referenced claim subject
- `issuer` MUST match the referenced claim issuer

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

Rules:

- `attestation_id` MUST reference an existing `attestation.issued` event
- `subject` MUST match the referenced attestation subject
- `issuer` MUST match the referenced attestation issuer

## Node validation

On `POST /events`, nodes MUST validate:

- event shape and required fields
- supported protocol version
- known event type
- event id matches canonical unsigned event hash
- Ed25519 signature verifies against `issuer`
- revocation references point to existing events of the expected type
- revocation `subject` and `issuer` match the referenced event

Nodes MUST NOT treat external claims as true merely because the event is valid.

## HTTP API

- `GET /health`
- `GET /info`
- `POST /events`
- `POST /events/validate`
- `POST /events/batch`
- `GET /events/{id}`
- `GET /events?subject=...&issuer=...&type=...&after_created_at=...&after_id=...&limit=...`
- `GET /identities/{pubkey}/events`

### Event validation

`POST /events/validate` accepts a signed event and validates it without storing it. The validation result includes event shape, ID, signature, reference checks, and ID conflict checks:

```json
{
  "valid": true,
  "error": null
}
```

For invalid events:

```json
{
  "valid": false,
  "error": "event id mismatch"
}
```

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

Batch submission is idempotent: submitting an already stored valid event is still accepted and does not create a duplicate. If a node already stores an event with the same `id` but different event content, it MUST reject the submitted event as an ID conflict.

### Event listing cursor

`GET /events` returns events ordered by:

```text
created_at ASC, id ASC
```

Optional query parameters:

- `subject`
- `issuer`
- `type`
- `after_created_at`
- `after_id`
- `limit`

Cursor semantics:

```sql
created_at > after_created_at
OR (created_at = after_created_at AND id > after_id)
```

`after_id` requires `after_created_at`. If `after_created_at` is provided without `after_id`, nodes return events with `created_at > after_created_at`.

Nodes default to `limit=500` when no limit is provided.

## Peer sync

TIP 0.1 sync is intentionally simple and implementation-level. The protocol primitives are:

- incremental reads via `GET /events` cursor pagination
- idempotent writes via `POST /events` or `POST /events/batch`

The reference node supports explicit peer lists, manual pull sync, opt-in startup sync, and persistent per-peer cursor state. This is not peer discovery, consensus, or a guarantee that all nodes converge globally.

A node may store, per peer:

```text
peer_url
last_created_at
last_id
updated_at
```

A later sync can resume by querying:

```text
GET /events?after_created_at=<last_created_at>&after_id=<last_id>&limit=500
```

## Privacy and safety

TIP 0.1 is a public event layer. Publishing an event to a node makes it public. Revocation can add new evidence, but cannot erase already replicated data.
