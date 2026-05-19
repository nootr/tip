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
