# zixcel-topology-api

A metadata-only Rust API projecting services, repositories, GitHub organizations, deployments and external services into one contract. It stores neither customer bodies nor authentication values; SQLite and HTTP listeners stay within a local boundary.

```bash
ZIXCEL_STATE="$(pwd)/state"
mkdir -m 700 -p "${ZIXCEL_STATE}"
cargo run --offline -- import-source "${ZIXCEL_STATE}/topology.sqlite3" < topology-source.json
mkdir -m 700 -p /absolute/private/identity
cargo run --offline -- generate-identity \
  /absolute/private/identity/signing-key.json \
  /absolute/private/identity/trust-bundle.json \
  example-domain example-deployment example-client
cargo run --offline -- serve-authenticated \
  state/topology.sqlite3 127.0.0.1:4211 \
  /absolute/private/identity/signing-key.json
```

Read APIs are `GET /health`, `GET /v1/topology` and `GET /v1/nodes/{node-id}`. `/v1` requires a caller-generated 256-bit nonce and the audience configured in the signing identity. Ed25519 signatures bind method, URL, nonce, status, body hash, signer label, deployment, security domain, key revision and expiry. The caller retains the corresponding public-key pin. Missing nonce or audience yields 401.

Create private keys and public-key pins at owner-only non-symlink absolute paths, without overwriting existing files. Rotation creates a separate identity and explicitly switches the public-key pin. Callers supply security domain, deployment identifier and audience explicitly when generating an identity. Existing v1 identities retain their configured audience and are not rewritten.

Signatures establish response authenticity only. They cannot distinguish same-UID processes sharing a software private key and provide no workload attestation, Crowsi trust bundle or monotonic-clock evidence. Callers decide connection status only after separately verifying the required workload evidence.

Provider failures are normalized by `disconnect DB NODE ERROR-CODE` to `connection_state=disconnected`. Never store raw exceptions, URL credentials or tokens in databases or responses.

Callers project their metadata into the provider-owned `zixcel://topology/source/v1` contract. The API reads bounded stdin JSON validated against closed schemas, a 1 MiB bound and SHA-256. SQLite is built as a new owner-only file, integrity-checked, fsynced and atomically replaced to prevent previous input remaining in free pages. SQLite and JSON snapshots stay under this repository's `state/`.

## Package integration

The package is an independently consumable unit. Callers reference its documented
interface through a versioned dependency and own application-specific composition
and integration.
