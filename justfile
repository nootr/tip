set shell := ["bash", "-eu", "-o", "pipefail", "-c"]

_default:
    just --list

fmt:
    cargo fmt

test:
    cargo test --all-targets

lint:
    cargo clippy --all-targets -- -D warnings

check: fmt test lint

install-hooks:
    git config core.hooksPath .githooks

vectors:
    cargo run -p tip-core --example generate_test_vectors > test-vectors/tip-0.1.json

node port="8080":
    cargo run -p tip-node -- serve --bind "127.0.0.1:{{port}}"
