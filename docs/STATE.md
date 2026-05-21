# State of TIP

Current status after `v0.1.0-alpha.5`.

TIP is a portable signed trust-evidence protocol. It is not a global reputation score, a consensus network, a blockchain, or a claim-verification oracle.

## What exists

- Rust workspace with `tip-core`, `tip-cli`, and `tip-node`.
- Static homepage and protocol documentation.
- Signed TIP 0.1 events using Ed25519, JCS/RFC 8785 canonical JSON, and SHA-256 event IDs.
- Event types for identities, claims, attestations, and revocations.
- SQLite-backed HTTP node with event ingestion, validation, query, projections, node-local sequence sync, peer sync, known-peer tracking, persistent node identity, and community metadata.
- CLI for keys, event creation/submission/validation, query, trust explain/evaluate, and portable bundles.
- Portable bundles with raw events plus active projections and semantic verification.
- Release pipeline with binary archives and checksums.
- Test vectors for events and bundles.

## Current architecture

Rust code follows hexagonal architecture:

- `tip-core`: domain model, ports, use-cases, crypto verification/signing helpers, no concrete IO.
- `tip-cli`: filesystem, HTTP, policy, and bundle UX.
- `tip-node`: HTTP and SQLite adapters around `tip-core` use-cases.

The node is deliberately a cache/transport layer. Trust decisions remain client-side policy decisions.

## Trust and threat model

Core rule:

> A TIP node is not an authority. A node is an untrusted cache for cryptographically verifiable events.

A malicious or faulty node can:

- omit events, especially revocations
- serve stale data
- reorder events
- censor subjects or issuers
- lie in descriptive metadata
- disappear or fork its local view

Existing mitigations:

- event ID, shape, canonical JSON, and signature verification
- conflict detection for same event ID with different content
- revocation reference validation
- out-of-order revocation retry during batch ingest and peer sync
- `tip trust evaluate` evidence-source metadata and completeness warnings
- node-local sequence sync for append-order replication cursors
- peer sync over node-local sequence cursors
- periodic peer sync and optional full resync as a cache-refresh safety valve
- configured peer node public-key pinning
- local known-peer tracking for peer inspection
- portable bundles that can be verified independently

Non-guarantees:

- absence from one node is not evidence of absence
- full resync is not a completeness proof
- pinned peers reduce endpoint impersonation, not censorship or omission risk
- node metadata is descriptive, not authenticated identity beyond node-key exposure
- known peers are candidates only, not sync peers or authorities

## Alpha.5 posture

`v0.1.0-alpha.5` is the first alpha with sequence-based node replication foundations.

Important alpha.5 changes:

- `tip trust evaluate` reports evidence source and completeness limitations
- `GET /sync/events` exposes node-local sequence pages
- peer sync uses sequence cursors instead of signer-controlled `created_at` cursors
- sync state persists `last_sequence` per peer
- configured/ad-hoc peers observed during sync are recorded in local `known_peers`
- `tip-node peers list` inspects local known-peer status
- peer gossip trust model documented: known peers are candidates, configured sync peers are locally approved replication sources, trusted issuers remain policy-level

The protocol is still alpha and allowed to break. Backwards compatibility is not a priority until real users and stable semantics exist.

## Peer discovery direction

Target model:

- **known peers** are gossiped candidates and are not trusted by default
- **sync peers** are locally configured, pinned replication sources
- **trusted issuers** are policy-level event issuers, separate from node peers

Future peer gossip should let nodes exchange candidate peer URLs and claimed node keys. Candidates may be stored locally for inspection, but MUST NOT be synced automatically and MUST NOT become trusted transitively. Local config remains the only authority for automatic sync.

Known-peer storage tracks:

```text
url
claimed_node_public_key
name
source_peer_url
first_seen_at
last_seen_at
last_verified_at
status
failure_count
```

Useful statuses include `candidate`, `reachable`, `key_mismatch`, `unreachable`, and `blocked`.

Current implementation records configured or ad-hoc peers observed during sync attempts in local `known_peers` storage and exposes them through `tip-node peers list` and read-only `GET /peers`. It does not yet ingest gossiped peers from other nodes.

Recommended next implementation order:

1. During sync with configured sync peers, ingest their gossiped peers as candidates only.
2. Add explicit promotion/import later; never silent auto-trust.

## Near roadmap

Recommended next work, in order:

1. Ingest gossiped peers from configured sync peers as candidates only.
2. Move bundle/projection verification helpers into `tip-core` so CLI is not the only implementation.
3. Add schemas/OpenAPI-style docs for node API and bundle format.
4. Explore signed checkpoints/transparency logs for stronger consistency evidence.

## Design guardrails

- Keep nodes neutral: no global trust score, no external proof verification by nodes.
- Keep trust policy client-side and auditable.
- Keep discovery candidate-only; do not auto-sync or auto-trust discovered peers.
- Treat revocations as high-priority safety evidence.
- Avoid token/staking incentives until trust semantics are mature.
