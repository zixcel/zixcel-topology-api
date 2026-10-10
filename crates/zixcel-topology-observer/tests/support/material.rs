use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use crowsi_local_control_bridge::{
    BridgeAction, ControlAuthorizationV2, ControlRequestV1, IpcAuthorizationEnvelopeV2,
    SenderProof, SignedAuthorization, canonical_authorization, canonical_request,
};
use ed25519_dalek::{Signer, SigningKey};
use ihat_identity_assertion_contracts::{
    CURRENT_DEVICE_STATUS_SCHEMA, CurrentDeviceStatusV1, DevicePostureV1, RevocationEpochsV1,
    canonical_current_status_payload,
};
use zixcel_topology_observer::{
    OBSERVATION_PURPOSE, ObservationBundleV1, TOPOLOGY_RESOURCE, TopologyObservationRequestV1,
    operation_body_sha256,
};

pub const WORKLOAD: &str = "spiffe://crowsi/local/coela-topology-client";

#[derive(Clone)]
pub struct AuthorizationOptions {
    pub workload: String,
    pub reservation: String,
    pub issued_offset_s: i64,
    pub expires_offset_s: i64,
}

impl Default for AuthorizationOptions {
    fn default() -> Self {
        Self {
            workload: WORKLOAD.into(),
            reservation: "reservation-topology-001".into(),
            issued_offset_s: -1,
            expires_offset_s: 30,
        }
    }
}

pub struct Material {
    pub bundle: ObservationBundleV1,
    pub pa_public_key: [u8; 32],
    pub status: CurrentDeviceStatusV1,
}

impl Material {
    pub fn new(request_url: &str, options: &AuthorizationOptions) -> Self {
        let operation = TopologyObservationRequestV1 {
            schema: "crowsi://topology-observer/request/v1".into(),
            request_url: request_url.into(),
            request_nonce: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([3_u8; 32]),
            maximum_response_bytes: 1_048_576,
        };
        let control = ControlRequestV1 {
            schema: "crowsi://local-control/request/v1".into(),
            request_id: "request-topology-001".into(),
            action: BridgeAction::ObserveProvider,
            resource: TOPOLOGY_RESOURCE.into(),
            purpose: OBSERVATION_PURPOSE.into(),
            body_sha256: operation_body_sha256(&operation).expect("operation digest"),
        };
        let pa = SigningKey::from_bytes(&[7; 32]);
        let sender = SigningKey::from_bytes(&[8; 32]);
        let document = authorization(&control, options, &sender);
        let status = current_status(&document);
        let authorization = SignedAuthorization {
            signature_hex: hex::encode(pa.sign(&canonical_authorization(&document)).to_bytes()),
            document,
        };
        let sender_proof = SenderProof {
            signature_hex: hex::encode(sender.sign(&canonical_request(&control)).to_bytes()),
        };
        Self {
            bundle: ObservationBundleV1 {
                schema: "crowsi://topology-observer/bundle/v1".into(),
                authorization: IpcAuthorizationEnvelopeV2 {
                    schema: "crowsi://local-control/ipc-envelope/v2".into(),
                    request: control,
                    authorization,
                    sender_proof,
                },
                operation,
            },
            pa_public_key: pa.verifying_key().to_bytes(),
            status,
        }
    }
}

fn authorization(
    request: &ControlRequestV1,
    options: &AuthorizationOptions,
    sender: &SigningKey,
) -> ControlAuthorizationV2 {
    let now = i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_secs(),
    )
    .expect("representable time");
    ControlAuthorizationV2 {
        schema: "crowsi://local-control/authorization/v2".into(),
        issuer: "crowsi-policy-administrator".into(),
        audience: "crowsi-local-control-bridge".into(),
        service_id: "service:crowsi".into(),
        pairwise_subject: "pairwise:crowsi:topology-fixture".into(),
        device_id: "device:topology-workstation-a".into(),
        device_proof_key_ref: "keyref:device:topology-workstation-a".into(),
        session_ref: "sref_topology_fixture_01".into(),
        device_posture: "compliant".into(),
        device_posture_revision: 4,
        subject_revocation_epoch: 3,
        service_revocation_epoch: 2,
        device_revocation_epoch: 4,
        session_revocation_epoch: 5,
        workload_id: options.workload.clone(),
        actor_profile_id: "profile-topology-operator".into(),
        assurance: "phishing-resistant".into(),
        user_verification: true,
        sender_public_key_hex: hex::encode(sender.verifying_key().to_bytes()),
        request_id: request.request_id.clone(),
        action: request.action,
        resource: request.resource.clone(),
        purpose: request.purpose.clone(),
        body_sha256: request.body_sha256.clone(),
        reservation_id: options.reservation.clone(),
        issued_at_epoch_s: now + options.issued_offset_s,
        expires_at_epoch_s: now + options.expires_offset_s,
    }
}

include!("material_status.rs");
