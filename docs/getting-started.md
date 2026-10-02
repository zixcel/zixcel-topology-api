# Using zixcel-topology-api

Serve a bounded metadata view of registered service, organization and deployment relationships.

## Before you start

Operational records are supplied through registration. The API does not discover infrastructure or authorize changes.

## First steps

Run from the repository root:

```sh
cargo test --locked
```

## How to assess the result

- Validate registered topology inputs.
- Expose selected relationships through a local API.

A passing source-level check establishes only what that check observes. Keep missing configuration, unavailable services and unverified deployment paths visible.

## Continue reading

[Repository overview](../README.md)
