# Using zixcel-topology-observer

Acquire a topology view only after checking authorization and source authenticity.

## Before you start

The operator supplies registered endpoints and trust. Acquisition does not establish ownership or permission to alter the topology.

## First steps

Run from the repository root:

```sh
cargo test --locked
```

## How to assess the result

- Validate the configured topology exchange.
- Return a bounded, verified observation.

A passing source-level check establishes only what that check observes. Keep missing configuration, unavailable services and unverified deployment paths visible.

## Continue reading

[Repository overview](../README.md)
