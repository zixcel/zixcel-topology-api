use crowsi_local_control_bridge::IpcAuthorizationEnvelopeV2;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TopologyObservationRequestV1 {
    pub schema: String,
    pub request_url: String,
    pub request_nonce: String,
    pub maximum_response_bytes: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ObservationBundleV1 {
    pub schema: String,
    pub authorization: IpcAuthorizationEnvelopeV2,
    pub operation: TopologyObservationRequestV1,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ObservationReceiptV1 {
    pub schema: String,
    pub state: String,
    pub crowsi: CrowsiObservationEvidenceV1,
    pub response: VerifiedResponseEvidenceV1,
    pub body_base64url: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
pub struct CrowsiObservationEvidenceV1 {
    pub evidence_kind: String,
    pub authorization_consumed: bool,
    pub kernel_peer_verified: bool,
    pub executable_digest_verified: bool,
    pub workload_binding_verified: bool,
    pub trusted_monotonic_replay_verified: bool,
    pub command_digest: String,
    pub authorized_at_epoch_s: i64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VerifiedResponseEvidenceV1 {
    pub evidence_kind: String,
    pub issuer: String,
    pub audience: String,
    pub signer_id: String,
    pub security_domain: String,
    pub deployment_id: String,
    pub trust_revision: u64,
    pub request_url: String,
    pub request_nonce: String,
    pub response_status: u16,
    pub body_sha256: String,
    pub proof_key_thumbprint: String,
    pub issued_at_epoch_s: i64,
    pub expires_at_epoch_s: i64,
}
