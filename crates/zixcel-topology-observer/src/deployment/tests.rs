use std::{
    fs,
    os::unix::fs::PermissionsExt,
    time::{SystemTime, UNIX_EPOCH},
};

use ed25519_dalek::{Signer, SigningKey};
use ihat_identity_assertion_contracts::{
    CURRENT_DEVICE_STATUS_SCHEMA, CurrentDeviceStatusV1, DevicePostureV1, RevocationEpochsV1,
    canonical_current_status_payload,
};

use super::{DeploymentV3, IdentityStatusDeploymentV2, compose_bridge};

#[test]
fn exact_device_a_status_bootstraps_the_bridge() {
    let fixture = Fixture::new("service:crowsi", "device:topology-a");
    assert!(compose_bridge(&fixture.config).is_ok());
}

#[test]
fn wrong_service_status_is_rejected() {
    let fixture = Fixture::new("service:other", "device:topology-a");
    assert!(compose_bridge(&fixture.config).is_err());
}

#[test]
fn device_b_status_cannot_bootstrap_device_a() {
    let fixture = Fixture::new("service:crowsi", "device:topology-b");
    assert!(compose_bridge(&fixture.config).is_err());
}

#[test]
fn missing_status_wire_fails_before_socket_creation() {
    let fixture = Fixture::new("service:crowsi", "device:topology-a");
    fs::remove_file(fixture.root.path().join("current-device-status.json")).expect("remove status");
    assert!(compose_bridge(&fixture.config).is_err());
}

struct Fixture {
    root: tempfile::TempDir,
    config: DeploymentV3,
}

impl DeploymentV3 {
    fn test_fixture(
        root: &std::path::Path,
        pa: [u8; 32],
        status_key: [u8; 32],
        status_path: std::path::PathBuf,
    ) -> Self {
        Self {
            schema: "crowsi://topology-observer/deployment/v3".into(),
            socket_path: root.join("observer.sock"),
            bridge_state_path: root.join("bridge.sqlite3"),
            response_state_path: root.join("response.sqlite3"),
            response_trust_path: root.join("response-trust.json"),
            request_url: "https://topology.invalid/v1".into(),
            pa_public_key_hex: hex::encode(pa),
            caller_uid: nix::unistd::Uid::effective().as_raw(),
            caller_gid: nix::unistd::Gid::effective().as_raw(),
            workload_id: "spiffe://crowsi/local/coela-topology-client".into(),
            client_executable_sha256: format!("sha256:{}", "1".repeat(64)),
            rate_limit_per_minute: 20,
            identity_status: IdentityStatusDeploymentV2 {
                public_key_hex: hex::encode(status_key),
                key_id: "ihat-status-key:topology:1".into(),
                issuer: "ihat://identity-authority".into(),
                audience: "crowsi://topology-observer/current-status".into(),
                service_id: "service:crowsi".into(),
                path: status_path,
                pairwise_subject: "pairwise:crowsi:topology-observer".into(),
                device_id: "device:topology-a".into(),
                device_proof_key_ref: "keyref:topology-a".into(),
                session_ref: "sref_topology_session_01".into(),
            },
        }
    }
}

impl Fixture {
    fn new(status_service: &str, status_device: &str) -> Self {
        let root = tempfile::tempdir().expect("temporary directory");
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).expect("private root");
        let pa = SigningKey::from_bytes(&[42; 32]);
        let status_key = SigningKey::from_bytes(&[43; 32]);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_secs();
        let proof = if status_device.ends_with('a') {
            "keyref:topology-a"
        } else {
            "keyref:topology-b"
        };
        let mut status = CurrentDeviceStatusV1 {
            schema: CURRENT_DEVICE_STATUS_SCHEMA.into(),
            issuer: "ihat://identity-authority".into(),
            audience: "crowsi://topology-observer/current-status".into(),
            service_id: status_service.into(),
            pairwise_subject: "pairwise:crowsi:topology-observer".into(),
            device_id: status_device.into(),
            device_proof_key_ref: proof.into(),
            session_ref: "sref_topology_session_01".into(),
            device_posture: DevicePostureV1 {
                state: "compliant".into(),
                revision: 4,
            },
            revocation_epochs: RevocationEpochsV1 {
                subject: 3,
                service: 2,
                device: 4,
                session: 5,
            },
            issued_at_epoch_s: now.saturating_sub(1),
            expires_at_epoch_s: now + 20,
            nonce: format!("status:{status_service}:{status_device}"),
            key_id: "ihat-status-key:topology:1".into(),
            signature: String::new(),
        };
        status.signature = hex::encode(
            status_key
                .sign(&canonical_current_status_payload(&status))
                .to_bytes(),
        );
        let status_path = root.path().join("current-device-status.json");
        fs::write(
            &status_path,
            serde_json::to_vec(&status).expect("status JSON"),
        )
        .expect("status");
        fs::set_permissions(&status_path, fs::Permissions::from_mode(0o600)).expect("status mode");
        let config = DeploymentV3::test_fixture(
            root.path(),
            pa.verifying_key().to_bytes(),
            status_key.verifying_key().to_bytes(),
            status_path,
        );
        Self { root, config }
    }
}
