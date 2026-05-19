# Security Policy

TIP is early alpha software for cryptographic trust evidence. Treat the current implementation as experimental until the protocol and codebase have received broader review.

## Supported versions

Only the latest alpha release and the current `main` branch are supported for security fixes.

| Version | Supported |
| ------- | --------- |
| latest alpha | Yes |
| older alpha releases | No |

## Reporting a vulnerability

Please do not open public GitHub issues for suspected vulnerabilities.

Use GitHub private vulnerability reporting / Security Advisories for this repository when available. Include:

- affected component (`tip-core`, `tip-cli`, `tip-node`, release workflow, or spec)
- impact and attack scenario
- reproduction steps or proof of concept
- affected version, commit, or release
- any suggested fix or mitigation

If GitHub private reporting is not available, open a minimal public issue asking for a private security contact without disclosing exploit details.

## Malicious node model

TIP nodes are untrusted caches and transport peers. They are not trust authorities.

A malicious node may serve stale or incomplete data, omit revocations, reorder events, censor submissions, or publish misleading `/info` metadata. Signatures and event IDs protect integrity, but they do not prove completeness.

Mitigations for users and integrators:

- verify every event signature and event ID client-side
- do not treat absence from one node as evidence that an event does not exist
- evaluate trust from multiple independent nodes and/or verified bundles when decisions matter
- treat valid revocations from any source as overriding the referenced active event
- treat node metadata as descriptive only, not authenticated identity

The implementation retries out-of-order revocations during batch submission and peer sync when the referenced event appears later in the same ingestion stream. This reduces accidental stale projections, but it does not provide global completeness guarantees.

## Scope

Security-sensitive areas include:

- event canonicalization and hashing
- Ed25519 signature verification
- event validation and revocation logic
- node HTTP ingestion and peer sync
- release artifacts and checksums
- key storage behavior in CLI/node adapters

## Disclosure

Maintainers will aim to acknowledge reports quickly, assess severity, prepare a fix, and publish release notes after a patched release is available.

There is currently no bug bounty program.
