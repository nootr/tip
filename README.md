# TIP — Trust Infrastructure Protocol

TIP is portable cryptographic trust infrastructure for the internet.

It lets users, communities, platforms, and agents exchange verifiable public evidence as signed events: identity creation, claims, attestations, and revocations. TIP is not a universal reputation score and does not require a blockchain.

## Repository layout

- `SPEC.md` — TIP 0.1 protocol draft
- `crates/tip-core` — pure domain model, ports, use-cases, and crypto primitives
- `crates/tip-node` — lightweight HTTP node with SQLite event storage
- `crates/tip-cli` — command-line client
- `site/` — static homepage for GitHub Pages

## Architecture

Rust code follows hexagonal architecture:

- domain and use-cases live in `tip-core`
- IO is behind ports/traits
- SQLite, HTTP, and filesystem key storage are adapters
- tests target core behavior without requiring a running node

## Quick start

```bash
cargo test
cargo run -p tip-cli -- key generate --name default
cargo run -p tip-cli -- identity create --out identity.json
cargo run -p tip-node
cargo run -p tip-cli -- event submit identity.json --node http://127.0.0.1:8080
cargo run -p tip-cli -- query --subject <public-key> --node http://127.0.0.1:8080
```

Optional developer shortcuts use [`just`](https://github.com/casey/just):

```bash
just check
just node
just vectors
```

## Git hooks

Local hooks live in `.githooks/`. Enable them per clone with:

```bash
git config core.hooksPath .githooks
# or
just install-hooks
```

The pre-commit hook runs non-mutating checks:

- `cargo fmt --all -- --check`
- `cargo test --all-targets`
- `cargo clippy --all-targets -- -D warnings`

## Status

Early 0.1 skeleton. The node is currently a single-node SQLite-backed HTTP event store with a persistent local node identity key, designed to grow into a decentralized peer-synced network later.

## License

MIT
