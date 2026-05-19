# TIP — Trust Infrastructure Protocol

TIP is portable cryptographic trust infrastructure for the internet.

It lets users, communities, platforms, and agents exchange verifiable public evidence as signed events: identity creation, claims, attestations, and revocations. TIP is not a universal reputation score and does not require a blockchain.

## Repository layout

- `SPEC.md` — TIP 0.1 protocol draft
- `CHANGELOG.md` — release notes
- `CONTRIBUTING.md` — contributor guide
- `SECURITY.md` — vulnerability reporting policy
- `crates/tip-core` — pure domain model, ports, use-cases, and crypto primitives
- `crates/tip-node` — lightweight HTTP node with SQLite event storage and explicit peer sync
- `crates/tip-cli` — command-line client
- `site/` — static homepage for GitHub Pages

## Architecture

Rust code follows hexagonal architecture:

- domain and use-cases live in `tip-core`
- IO is behind ports/traits
- SQLite, HTTP, and filesystem key storage are adapters
- tests target core behavior without requiring a running node

## Installation

From source:

```bash
cargo install --path crates/tip-cli
cargo install --path crates/tip-node
```

Released binaries are published on GitHub Releases for Linux x86_64 and macOS arm64/x86_64.

Verify downloaded release archives with the matching checksum file:

```bash
shasum -a 256 -c tip-x86_64-unknown-linux-gnu.tar.gz.sha256
```

## Run a node

Create a config from the example:

```bash
cp tip-node.example.toml tip-node.toml
```

Run the node:

```bash
tip-node serve --config tip-node.toml
```

Or with Cargo during development:

```bash
cargo run -p tip-node -- serve --config tip-node.toml
```

The node exposes:

- `GET /health`
- `GET /info`
- `POST /events`
- `POST /events/validate`
- `POST /events/batch`
- `GET /events?...`
- `GET /events/{id}`
- `GET /identities/{pubkey}/claims`
- `GET /identities/{pubkey}/attestations`

## Config file

```toml
[node]
bind = "127.0.0.1:8080"
db = "tip-node.sqlite3"
key = "tip-node-key.json"

[sync]
on_start = false
limit = 500
from_beginning = false

[peers]
urls = [
  "http://127.0.0.1:8081",
  "http://127.0.0.1:8082",
]
```

CLI flags and environment variables override config values where available:

- `TIP_NODE_BIND`
- `TIP_NODE_DB`
- `TIP_NODE_KEY`

## Create and submit events

Generate a local development key:

```bash
tip key generate --name default
```

Create an identity event:

```bash
tip identity create --out identity.json
```

Add a GitHub claim:

```bash
tip claim add github joris \
  --proof-url https://gist.github.com/joris/tip-proof \
  --out claim.json
```

Submit events to a node:

```bash
tip event submit identity.json --node http://127.0.0.1:8080
tip event validate identity.json --node http://127.0.0.1:8080
tip event submit-batch identity.json claim.json --node http://127.0.0.1:8080
```

Query events:

```bash
tip query --subject <public-key> --limit 100 --node http://127.0.0.1:8080
tip query claims --subject <public-key> --node http://127.0.0.1:8080
tip query attestations --subject <public-key> --node http://127.0.0.1:8080
```

Use cursor pagination:

```bash
tip query \
  --after-created-at 1700000000 \
  --after-id sha256:... \
  --limit 500 \
  --node http://127.0.0.1:8080
```

## Peer sync

TIP currently supports explicit peer lists. There is no peer discovery yet.

Manual one-shot sync from a peer:

```bash
tip-node sync --peer http://127.0.0.1:8081 --db tip-node.sqlite3
```

Manual sync from configured peers:

```bash
tip-node sync --config tip-node.toml
```

Force a full resync from the beginning:

```bash
tip-node sync --peer http://127.0.0.1:8081 --from-beginning
```

Opt-in startup sync:

```toml
[sync]
on_start = true
```

Then:

```bash
tip-node serve --config tip-node.toml
```

Sync state is persisted per peer in SQLite, so later syncs resume from the last seen `(created_at, id)` cursor.

## Development

```bash
cargo test
just check
just node
just vectors
```

Optional developer shortcuts use [`just`](https://github.com/casey/just).

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

Early 0.1 alpha. The node is currently a SQLite-backed HTTP event store with explicit peer sync, persistent local node identity, and persistent peer sync state.

## License

MIT
