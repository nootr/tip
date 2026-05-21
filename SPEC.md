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

Nodes SHOULD handle out-of-order ingestion defensively. For batch submission and peer sync, events that fail only because a referenced claim or attestation is not available yet SHOULD be retried after other valid events from the same batch/page stream have been accepted. Permanent validation failures, such as invalid signatures, ID conflicts, wrong reference types, or subject/issuer mismatches, MUST remain rejected.

## Node trust model

TIP nodes are untrusted transport and cache infrastructure. A node is not an authority over trust, completeness, or truth.

A malicious or faulty node can:

- omit valid events, including revocations
- serve stale data
- delay or reorder events during sync
- refuse submissions or selectively censor subjects/issuers
- advertise misleading `/info` metadata

Clients MUST verify event IDs, canonical payloads, and signatures before using events. Clients MUST NOT treat absence from a single node as proof that an event or revocation does not exist. For trust decisions, clients SHOULD prefer evidence gathered from multiple independent nodes and/or portable bundles. When valid revocations are found from any source, projection logic MUST apply them to the referenced claim or attestation.

Node `/info` metadata is descriptive only. It is not authenticated by TIP 0.1 and MUST NOT be used as a trust anchor by itself.

## HTTP API

- `GET /health`
- `GET /info`
- `POST /events`
- `POST /events/validate`
- `POST /events/batch`
- `GET /events/{id}`
- `GET /events?subject=...&issuer=...&type=...&after_created_at=...&after_id=...&limit=...`
- `GET /sync/events?after_sequence=...&limit=...`
- `GET /peers?status=...&limit=...`
- `GET /identities/{pubkey}/events`
- `GET /identities/{pubkey}/claims`
- `GET /identities/{pubkey}/attestations`

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

Batch submission SHOULD accept out-of-order valid revocations when the referenced event is present elsewhere in the same batch.

### Identity projections

`GET /identities/{pubkey}/claims` returns active `claim.added` events for the subject, excluding claims revoked by valid `claim.revoked` events.

`GET /identities/{pubkey}/attestations` returns active `attestation.issued` events for the subject, excluding attestations revoked by valid `attestation.revoked` events.

Projection endpoints are read models over stored events. They do not replace the append-only event log.

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

## Bundles

A TIP bundle is a portable transport artifact for moving verifiable evidence between nodes, clients, agents, and offline workflows. A bundle is not itself a signed TIP event and does not replace the append-only event log.

TIP 0.1 bundles use `version = "tip-bundle/0.1"` and contain:

```json
{
  "version": "tip-bundle/0.1",
  "subject": "<subject-public-key>",
  "events": [],
  "active_claims": [],
  "active_attestations": []
}
```

Fields:

- `subject`: subject public key for the bundled evidence
- `events`: signed TIP events for the subject, including raw event-log context such as revocations
- `active_claims`: active `claim.added` projection for the subject
- `active_attestations`: active `attestation.issued` projection for the subject

Bundle validation MUST verify:

- supported bundle version
- every event in `events` has `subject` equal to bundle `subject`
- every event in `events` passes normal TIP event ID, shape, and signature verification
- every event in `active_claims` and `active_attestations` is present in `events`
- `active_claims` exactly matches the active claim projection reconstructed from `events`
- `active_attestations` exactly matches the active attestation projection reconstructed from `events`

Bundles MAY be submitted to nodes by submitting their `events` array through normal event ingestion, for example `POST /events/batch`. Nodes still apply normal validation and may reject invalid or conflicting events.

## Peer sync

TIP 0.1 sync is intentionally simple and implementation-level. The protocol primitives are:

- incremental replication reads via `GET /sync/events` sequence pagination
- idempotent writes via `POST /events` or `POST /events/batch`

The reference node supports explicit configured peer nodes, manual pull sync, opt-in startup sync, optional periodic sync, optional periodic full resync, peer node-public-key pinning, and persistent per-peer sequence state. This is not peer discovery, consensus, or a guarantee that all nodes converge globally.

Configured peer nodes use:

```toml
[[peers.nodes]]
url = "https://tip.example.org"
expected_node_public_key = "<peer-node-public-key>"
name = "Example community node"
```

Before syncing a configured peer, a node SHOULD request `GET /info` and compare `node_public_key` with `expected_node_public_key` when configured. A mismatch MUST abort sync for that peer. Peer pinning reduces endpoint impersonation risk; it does not make the peer authoritative and does not prove event-log completeness.

A node may store, per peer:

```text
peer_url
last_sequence
updated_at
```

A later sync can resume by querying:

```text
GET /sync/events?after_sequence=<last_sequence>&limit=500
```

### Node-local sequence sync

Reference nodes expose a node-local replication cursor:

```text
GET /sync/events?after_sequence=<sequence>&limit=500
```

Response:

```json
{
  "events": [],
  "next_after_sequence": 123
}
```

`sequence` is assigned by the serving node when an event is first stored. It is useful for efficient replication from that node because it follows local append order rather than signer-controlled `created_at`. Reference node peer sync uses this sequence cursor directly. It is not part of the TIP event, is not signed, is not portable across nodes, and MUST NOT be treated as protocol truth.

## Peer discovery direction

TIP 0.1 does not automatically discover or trust peers. The intended discovery model is candidate gossip:

- nodes may exchange known peer candidates
- discovered peers are untrusted by default
- discovered peers MUST NOT be synced automatically
- local configuration remains the only authority for automatic sync peers
- no transitive trust is implied when a configured peer advertises another peer

The reference node stores locally known peers for inspection. The current implementation records configured or ad-hoc peers observed during sync attempts and exposes them through a bounded read-only `GET /peers` endpoint. `GET /peers` may be filtered by `status` and defaults to `limit=100`, with a maximum `limit=500`.

This endpoint exposes candidate metadata such as URL, claimed node public key, optional name, source, status, failure count, and first/last seen timestamps. Peer key pinning is still required before promoting a candidate to a configured sync peer.

Terminology:

- known peers: discovered candidates
- sync peers: locally configured and optionally pinned replication sources
- trusted issuers: policy-level event issuers

## Privacy and safety

TIP 0.1 is a public event layer. Publishing an event to a node makes it public. Revocation can add new evidence, but cannot erase already replicated data.
