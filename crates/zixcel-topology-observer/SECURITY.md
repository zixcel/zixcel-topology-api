# Security policy

This repository establishes a local observation path, not an identity issuer or
policy authority. Its trust inputs are a Crowsi PA public key, an exact client
executable digest, a SPIFFE workload identifier, and a Zixcel
response-authenticity public key. Deployment v2 additionally requires a separate
iHAT current-status key and exact issuer, audience, service, pairwise subject,
device, and device-proof-key binding. None is accepted from an HTTP request.

The observer rejects missing, stale, replayed, open, wrongly bound, or tampered
authorization and response evidence. It uses owner-only Unix IPC, kernel peer
credentials, process start-time checks, executable hashing, finite I/O
deadlines, bounded frames, strict JSON, and two separate durable replay stores.
Zixcel's signing key proves response bytes and deployment binding only; Crowsi
workload trust comes exclusively from the independently signed local-control
authorization path.

A same-UID compromise can still replace user-owned deployment files or launch
trusted binaries against an attacker-controlled owner directory. Production
therefore requires a dedicated service identity, a root-controlled parent with
a provisioned service-owned `0700` socket directory, a root-controlled
configuration source, immutable signed artifacts, hardware-backed PA/sender
keys, and a rollback-resistant trusted time source. Until those deployment
controls are attested, callers must display `unavailable`, not `ready`.

Never put provider credentials, bearer tokens, private signing keys, customer
data, or arbitrary URLs in the observation bundle or receipt. Report any
fallback to unsigned HTTP, reusable authorization, browser credential path,
unbounded frame, or positive readiness inferred only from file/key ownership as
a security defect.

## Private vulnerability reporting

Report vulnerabilities through this repository's GitHub private vulnerability reporting form. Do not put credentials, personal or customer data, or production certificate material in public issues or pull requests.
