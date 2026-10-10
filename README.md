# zixcel-topology-api

Serve a bounded metadata view of registered service, organization and deployment relationships.

## What you can do

- Validate registered topology inputs.
- Expose selected relationships through a local API.

## Current scope

Operational records are supplied through registration. The API does not discover infrastructure or authorize changes.

Package distribution is not activated by this documentation. Use the checked-in source and the declared dependency versions; published availability must be verified separately.

## Getting started

Install Rust 1.97 or newer and make the declared dependencies available. Use the configured private registry when a dependency is not distributed publicly. Run from this repository:

```sh
cargo test --locked
```

## Documentation and source

[Usage guide](docs/getting-started.md)

[Examples](examples) · [Implementation and public interfaces](src) · [Verification cases](tests) · [Contributing](CONTRIBUTING.md) · [Security reporting](SECURITY.md) · [License](LICENSE) · [Attribution notices](NOTICE)


## Operational topology workspace

`crates/zixcel-topology-observer` is the authenticated observer for this Zixcel
topology service. Generic host network observation remains a Crowsi transport
component. This service manages operational metadata, not credential values.

```sh
cargo test --locked --workspace --all-targets
```

Use the observer with an explicitly trusted topology endpoint and verified
authorization. A supplied topology snapshot is not physical network discovery
or evidence that an infrastructure change actually completed.
