# Contributing to TIP

Thanks for helping improve TIP. The project is intentionally small and conservative: correctness and clarity matter more than feature volume.

## Development setup

Install Rust stable and clone the repository.

```bash
cargo test
```

Optional developer shortcuts use [`just`](https://github.com/casey/just):

```bash
just check
just node
just vectors
```

Enable local hooks:

```bash
just install-hooks
# or
git config core.hooksPath .githooks
```

The pre-commit hook runs:

```bash
cargo fmt --all -- --check
cargo test --all-targets
cargo clippy --all-targets -- -D warnings
```

## Architecture rules

Rust code follows hexagonal architecture.

- `crates/tip-core` contains domain types, ports, use-cases, and crypto primitives.
- `tip-core` must not depend on concrete IO such as filesystem, HTTP servers, SQLite, process environment, or clocks outside ports.
- IO belongs in adapters such as `tip-cli` and `tip-node`.
- Behavior changes should be covered by focused tests.
- Prefer small, explicit types over broad abstractions.

## Protocol changes

Protocol-facing changes should update all relevant places:

- `SPEC.md`
- `test-vectors/`
- `crates/tip-core` validation/signing tests
- `README.md` when user-facing behavior changes
- `CHANGELOG.md` under `Unreleased`

TIP 0.1 uses JCS/RFC8785 canonical JSON and rejects floating point numbers in event payloads.

## Commit style

Use Conventional Commits:

```text
feat(node): add configured peer sync
fix(cli): accept hyphenated key values
docs: update sync documentation
chore(release): publish checksums
```

Keep commits focused. Do not mix unrelated refactors, docs, and behavior changes unless they are part of the same small change.

## Pull request checklist

Before opening a PR, run:

```bash
just check
```

Also verify:

- no secrets, private keys, `.env` files, or local databases are committed
- generated test vectors are intentional
- docs/spec/changelog are updated when behavior changes
- release workflow changes are tested with a dry-run when possible

## Security issues

Do not report vulnerabilities in public issues. See `SECURITY.md`.
