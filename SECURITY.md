# Security policy

Zixcel Topology API exposes metadata only. Customer content, provider
credentials, access tokens, private signing keys, and local credential values
must never enter its SQLite database or response body.

The signed-response `/v1` surface is limited to numeric loopback and requires a
fresh request nonce. Ed25519 responses bind the audience, signer label,
security domain, deployment, key revision, method, URL, status, body digest,
key thumbprint, issue time, and expiry. This proves response authenticity only.
It is not workload attestation, a Crowsi trust bundle, a trusted monotonic
clock, or caller authorization. A reachable port, bearer token, request header,
software signing key held by the current OS user, or a valid signature alone
is not sufficient workload identity.

Private identities must use absolute, non-symlink paths beneath an owner-only
directory. The private identity must remain mode 0600 and is never overwritten
automatically. The public trust bundle may be distributed only through a
reviewed configuration path. Do not commit either local identity file.

The local software-held Ed25519 identity supports response-integrity testing.
Production federation must add independently verified SPIFFE or equivalent
workload evidence and a trusted monotonic clock; TPM or HSM custody can further
protect the signer. Report unsigned fallback, replay acceptance, public-key-pin
replacement, secret exposure, public binding, or response-size bypass as a
security defect.

## Common OSS security reporting


## Reporting a vulnerability

Use this repository's Security tab and **Report a vulnerability** to submit a private
report to maintainers. Do not open a public issue or pull request containing exploit
details, credentials, customer data, or personal information. If private reporting
is unavailable, use GitHub's private security-support channel and request a private
reporting route before disclosing details.

Include affected versions, a minimal synthetic reproduction, expected and observed
behavior, and impact. Remove real secrets and identifying data. Maintainers assess
the report and coordinate a correction and disclosure. No response-time guarantee,
bounty, or support contract is implied.

## Supported versions

The current main branch is maintained during development. Released-version support
is stated in release notes; older releases are not implicitly supported. Do not infer
runtime safety from a source scan or a passing CI policy check. Dependencies,
deployments, history, and application-specific authorization require their own checks.
