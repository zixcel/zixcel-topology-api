use base64::Engine;
use crowsi_local_control_bridge::{DispatchTicket, TrustedClock};
use ed25519_dalek::{Signature, Verifier};
use serde::Deserialize;

use crate::{
    CrowsiObservationEvidenceV1, ObservationReceiptV1, ObserverError, ResponseReplayStore,
    TopologyObservationRequestV1, VerifiedResponseEvidenceV1, ZixcelResponseTrust,
    http::WireResponse,
    proof_wire::{decode, signed_message},
    sha256_digest,
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ResponseProof {
    schema: String,
    algorithm: String,
    issuer: String,
    audience: String,
    workload_id: String,
    security_domain: String,
    deployment_id: String,
    trust_revision: u64,
    request_method: String,
    request_url: String,
    request_nonce: String,
    response_status: u16,
    body_sha256: String,
    proof_key_thumbprint: String,
    issued_at_epoch_s: i64,
    expires_at_epoch_s: i64,
}

pub(crate) fn verify<C: TrustedClock>(
    wire: WireResponse,
    request: &TopologyObservationRequestV1,
    ticket: &DispatchTicket,
    trust: &ZixcelResponseTrust,
    replay: &mut ResponseReplayStore,
    clock: &C,
) -> Result<ObservationReceiptV1, ObserverError> {
    if !clock.healthy() {
        return Err(ObserverError::Time);
    }
    let proof_bytes = decode(&wire.proof, 4_096)?;
    let signature_bytes = decode(&wire.signature, 64)?;
    if signature_bytes.len() != 64 {
        return Err(ObserverError::ResponseAuthenticity);
    }
    let proof: ResponseProof =
        serde_json::from_slice(&proof_bytes).map_err(|_| ObserverError::ResponseAuthenticity)?;
    let now = clock.now_epoch_s();
    validate(&proof, &wire, request, trust, now)?;
    let signature =
        Signature::from_slice(&signature_bytes).map_err(|_| ObserverError::ResponseAuthenticity)?;
    trust
        .key
        .verify(&signed_message(&proof_bytes, &wire.body), &signature)
        .map_err(|_| ObserverError::ResponseAuthenticity)?;
    replay.consume(&proof.request_nonce, &proof.body_sha256, now)?;
    Ok(receipt(proof, wire.body, ticket))
}

fn validate(
    proof: &ResponseProof,
    wire: &WireResponse,
    request: &TopologyObservationRequestV1,
    trust: &ZixcelResponseTrust,
    now: i64,
) -> Result<(), ObserverError> {
    let valid = proof.schema == "zixcel://topology/signed-response-proof/v1"
        && proof.algorithm == "Ed25519"
        && proof.issuer == trust.issuer
        && proof.audience == trust.audience
        && proof.workload_id == trust.signer_id
        && proof.security_domain == trust.security_domain
        && proof.deployment_id == trust.deployment_id
        && proof.trust_revision == trust.trust_revision
        && proof.request_method == "GET"
        && proof.request_url == request.request_url
        && proof.request_nonce == request.request_nonce
        && proof.response_status == wire.status
        && proof.body_sha256 == sha256_digest(&wire.body)
        && proof.proof_key_thumbprint == trust.thumbprint
        // Both local processes encode whole seconds; allow only their rounding boundary.
        && proof.issued_at_epoch_s <= now.saturating_add(1)
        && proof.issued_at_epoch_s >= now.saturating_sub(60)
        && proof.expires_at_epoch_s > now
        && proof
            .expires_at_epoch_s
            .saturating_sub(proof.issued_at_epoch_s)
            <= 60;
    valid
        .then_some(())
        .ok_or(ObserverError::ResponseAuthenticity)
}

fn receipt(proof: ResponseProof, body: Vec<u8>, ticket: &DispatchTicket) -> ObservationReceiptV1 {
    ObservationReceiptV1 {
        schema: "crowsi://topology-observer/receipt/v1".into(),
        state: "verified".into(),
        crowsi: CrowsiObservationEvidenceV1 {
            evidence_kind: "crowsi-pa-authorized-kernel-attested-workload".into(),
            authorization_consumed: true,
            kernel_peer_verified: true,
            executable_digest_verified: true,
            workload_binding_verified: true,
            trusted_monotonic_replay_verified: true,
            command_digest: ticket.command_digest.clone(),
            authorized_at_epoch_s: ticket.authorized_at_epoch_s,
        },
        response: VerifiedResponseEvidenceV1 {
            evidence_kind: "pinned-ed25519-response-signature".into(),
            issuer: proof.issuer,
            audience: proof.audience,
            signer_id: proof.workload_id,
            security_domain: proof.security_domain,
            deployment_id: proof.deployment_id,
            trust_revision: proof.trust_revision,
            request_url: proof.request_url,
            request_nonce: proof.request_nonce,
            response_status: proof.response_status,
            body_sha256: proof.body_sha256,
            proof_key_thumbprint: proof.proof_key_thumbprint,
            issued_at_epoch_s: proof.issued_at_epoch_s,
            expires_at_epoch_s: proof.expires_at_epoch_s,
        },
        body_base64url: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(body),
    }
}
