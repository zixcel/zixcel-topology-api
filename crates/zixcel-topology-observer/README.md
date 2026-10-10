# zixcel-topology-observer

Acquire a topology view only after checking authorization and source authenticity.

## What you can do

- Validate the configured topology exchange.
- Return a bounded, verified observation.

## Current scope

The operator supplies registered endpoints and trust. Acquisition does not establish ownership or permission to alter the topology.

Package distribution is not activated by this documentation. Use the owning product workspace and declared dependency versions. Registry availability is a separate release gate.

## Getting started

Install Rust 1.97 or newer. Run from the owning product workspace:

```sh
cargo test --locked -p zixcel-topology-observer
```

## Documentation and source

[Usage guide](docs/getting-started.md)

[Schemas](schemas) · [Implementation and public interfaces](src) · [Verification cases](tests) · [Contributing](CONTRIBUTING.md) · [Security reporting](SECURITY.md) · [License](LICENSE) · [Attribution notices](NOTICE)

## Product responsibility

This component is maintained in [zixcel/zixcel-topology-api](https://github.com/zixcel/zixcel-topology-api). Use the [product README](../../README.md) for composition, use cases and trust boundaries.
