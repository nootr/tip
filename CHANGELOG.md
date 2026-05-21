# Changelog

All notable changes to TIP are documented here.

This project uses pre-1.0 alpha releases while the protocol and reference implementation are still stabilizing.

## Unreleased

### Added

- Referential validation for claim and attestation revocation events.
- Event ID conflict detection for non-identical duplicate submissions.
- Read-only `POST /events/validate` node endpoint.
- `tip event validate` CLI command for node-side validation without publishing.
- Active claim and attestation projection use-cases and node endpoints.
- CLI query commands for active claims and attestations.
- `tip trust explain` command for summarizing active trust evidence for a subject.
- `tip trust evaluate` command for client-side TOML trust policies.
- Example `trust-policy.example.toml` included in release archives.
- Portable active trust evidence bundles via `tip bundle create`, `tip bundle verify`, `tip bundle submit`, and `tip trust evaluate --bundle`; bundles include raw events and active projections, with semantic projection verification.
- TIP bundle format documented in `SPEC.md`.
- `tip trust evaluate --bundle` can infer the subject from the bundle.
- Bundle format test vector for `tip-bundle/0.1`.
- Community node metadata in config and `/info` responses.
- Threat model documentation for malicious or incomplete nodes.
- Batch and peer-sync ingestion retry out-of-order revocations when referenced events arrive later in the same ingestion stream.
- Optional periodic peer sync and full-resync intervals for long-running nodes.
- Configured peers now use `[[peers.nodes]]` with optional node public-key pinning.
- GitHub Actions workflows opt into the Node.js 24 JavaScript action runtime.
- `docs/STATE.md` captures the current architecture, threat model, alpha.4 status, and near roadmap.
- `tip trust evaluate` output includes evidence source metadata and completeness warnings.
- Node-local sequence sync endpoint at `GET /sync/events` for efficient replication cursors.
- Peer sync now uses node-local sequence cursors instead of signer-controlled `created_at` cursors.
- Documented planned peer gossip model: shared known peers as untrusted candidates, configured sync peers only for automatic sync.
- Local `known_peers` storage and `tip-node peers list` for inspecting observed peer candidates/statuses.
- `docs/STATE.md` updated to reflect the alpha.5 sync/discovery posture.

## v0.1.0-alpha.2 - 2026-05-19

### Added

- Full `tip-node` config file support for node bind address, SQLite database path, node key path, sync options, and peer URLs.
- Release archive SHA-256 checksum files.
- Expanded README documentation for node operation, config, CLI usage, and peer sync.
- Improved GitHub Pages landing page.

### Changed

- `tip-node serve --config <path>` can now run directly from config values.
- `tip-node sync --config <path>` can use database and sync defaults from config.

## v0.1.0-alpha.1 - 2026-05-18

### Added

- Initial TIP 0.1 protocol draft.
- Rust workspace with `tip-core`, `tip-cli`, and `tip-node`.
- Ed25519 signed events using JCS/RFC8785 canonical JSON and SHA-256 event IDs.
- Event types for identity creation, claims, attestations, and revocations.
- CLI support for key generation, identity creation, claims, attestations, event verification, event submission, batch submission, and cursor queries.
- SQLite-backed HTTP node with persistent node identity key.
- HTTP API for health, node info, event submission, batch submission, event lookup, and cursor event listing.
- Explicit peer sync with manual sync, startup sync, and persistent per-peer cursor state.
- GitHub CI, GitHub Pages deployment, pre-commit checks, and binary release workflow.
- TIP 0.1 test vectors and conformance tests.

### Fixed

- CLI parsing for hyphenated base64url values.
