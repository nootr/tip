# TIP test vectors

`tip-0.1.json` contains deterministic Ed25519/JCS test vectors for TIP 0.1.

`tip-bundle-0.1.json` contains a deterministic bundle vector with raw events and reconstructed active projections.

They are generated with:

```bash
cargo run -p tip-core --example generate_test_vectors > test-vectors/tip-0.1.json
```

The seeds are included intentionally. These keys are public test fixtures only and must never be used for real identities.
