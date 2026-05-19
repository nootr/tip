# Changelog

All notable changes to TIP are documented here.

This project uses pre-1.0 alpha releases while the protocol and reference implementation are still stabilizing.

## Unreleased

### Added

- Referential validation for claim and attestation revocation events.

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
