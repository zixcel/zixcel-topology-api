# zixcel-topology-api

Maintain and expose registered service, organization and deployment relationships.
The authenticated observer lives in `crates/zixcel-topology-observer`; network
acquisition and framing belong to Crowsi, and security interpretation belongs to
vpremises-security. This service neither discovers infrastructure nor authorizes
an infrastructure change.

## Use cases

### Inspect readiness without contacting an endpoint

```sh
cargo run --locked -p zixcel-topology-observer -- sample-readiness
```

The JSON report states which deployment prerequisites remain unavailable. A
successful sample command does not provision identity, authorization or a service.

### Import and export an explicitly selected topology

Prepare a digest-bound `zixcel://topology/source/v1` document through the source
contract. Use an absolute, non-symlink database path in a private runtime directory:

```sh
cargo run --locked -p zixcel-topology-api -- import-source "$TOPOLOGY_DB" < source.json
cargo run --locked -p zixcel-topology-api -- export "$TOPOLOGY_DB" > exported.json
```

Import deliberately replaces the selected database with validated metadata.
Never import a private workstation catalog into an external publication pipeline.
A registered relationship is a declaration, not evidence of a physical connection.

### Submit a bounded authenticated observation

```sh
cargo run --locked -p zixcel-topology-observer -- observe "$OBSERVER_SOCKET" "$OBSERVATION_BUNDLE"
```

The caller provides owner-private configuration, a verified authorization and the
exact observation bundle. The observer verifies the trusted topology endpoint and
records bounded metadata; it cannot supply missing deployment trust or credentials.

## Build and verify

Requires Rust 1.97 or newer. Dependencies resolve from crates.io or this workspace;
no private registry, source catalog or adjacent checkout is required.

```sh
cargo fmt --all -- --check
cargo test --locked --workspace --all-targets --all-features
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo build --locked --workspace --bins
```

This workspace contains application executables, not a published Cargo library.
Deployment owns scheduling, identities, private runtime paths and endpoint trust.

[Observer](crates/zixcel-topology-observer/README.md) ·
[Usage](docs/getting-started.md) · [Source contract](src/source_contract.rs) ·
[Verification](tests) · [Contributing](CONTRIBUTING.md) ·
[Security](SECURITY.md) · [License](LICENSE) · [Notices](NOTICE)
