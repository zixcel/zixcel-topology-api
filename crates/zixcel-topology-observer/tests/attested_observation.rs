mod support;

use crowsi_local_control_bridge::BridgeError;
use support::{AuthorizationOptions, RuntimeFixture, Tamper};
use zixcel_topology_observer::ObserverError;

#[test]
fn offline_happy_path_requires_both_crowsi_and_zixcel_evidence() {
    let mut fixture = RuntimeFixture::new(&AuthorizationOptions::default());
    let exchange = fixture.exchange(Some(Tamper::None));
    let receipt = exchange.client.expect("verified observation");
    assert_eq!(exchange.server, Ok(()));
    assert_eq!(receipt.state, "verified");
    assert!(receipt.crowsi.authorization_consumed);
    assert!(receipt.crowsi.kernel_peer_verified);
    assert!(receipt.crowsi.executable_digest_verified);
    assert!(receipt.crowsi.workload_binding_verified);
    assert!(receipt.crowsi.trusted_monotonic_replay_verified);
    assert_eq!(
        receipt.response.evidence_kind,
        "pinned-ed25519-response-signature"
    );
    assert_eq!(receipt.response.audience, "observer-fixture-client");
    assert_eq!(receipt.response.deployment_id, "zixcel-topology-api-local");
}

#[test]
fn stale_authorization_is_rejected_before_topology_network_io() {
    let options = AuthorizationOptions {
        issued_offset_s: -120,
        expires_offset_s: -60,
        ..AuthorizationOptions::default()
    };
    let mut fixture = RuntimeFixture::new(&options);
    let exchange = fixture.exchange(None);
    assert_eq!(exchange.client, Err(ObserverError::Transport));
    assert_eq!(exchange.server, Err(BridgeError::Time));
}

#[test]
fn missing_authorization_is_rejected_before_topology_network_io() {
    let mut fixture = RuntimeFixture::new(&AuthorizationOptions::default());
    assert_eq!(
        fixture.reject_missing_authorization(),
        Err(BridgeError::Contract)
    );
}

#[test]
fn trailing_operation_bytes_are_rejected_before_topology_network_io() {
    let options = AuthorizationOptions {
        reservation: "reservation-topology-trailing".into(),
        ..AuthorizationOptions::default()
    };
    let mut fixture = RuntimeFixture::new(&options);
    assert_eq!(
        fixture.reject_trailing_operation(),
        Err(BridgeError::Contract)
    );
}

#[test]
fn wrong_workload_is_rejected_by_crowsi_trust() {
    let options = AuthorizationOptions {
        workload: "spiffe://crowsi/local/attacker".into(),
        ..AuthorizationOptions::default()
    };
    let mut fixture = RuntimeFixture::new(&options);
    let exchange = fixture.exchange(None);
    assert_eq!(exchange.server, Err(BridgeError::Authentication));
}

#[test]
fn wrong_executable_digest_is_rejected_from_kernel_peer_evidence() {
    let mut fixture = RuntimeFixture::with_executable(
        &AuthorizationOptions::default(),
        &format!("sha256:{}", "0".repeat(64)),
    );
    let exchange = fixture.exchange(None);
    assert_eq!(exchange.server, Err(BridgeError::PeerAttestation));
}

#[test]
fn consumed_authorization_cannot_be_replayed() {
    let options = AuthorizationOptions {
        reservation: "reservation-topology-replay".into(),
        ..AuthorizationOptions::default()
    };
    let mut fixture = RuntimeFixture::new(&options);
    let first = fixture.exchange(Some(Tamper::None));
    assert!(
        first.client.is_ok(),
        "client={:?} server={:?}",
        first.client,
        first.server
    );
    let replay = fixture.exchange(None);
    assert_eq!(replay.server, Err(BridgeError::Replay));
}

#[test]
fn tampered_body_signature_deployment_and_future_time_are_rejected() {
    for tamper in [
        Tamper::Body,
        Tamper::Signature,
        Tamper::Deployment,
        Tamper::Audience,
        Tamper::Future,
    ] {
        let options = AuthorizationOptions {
            reservation: format!("reservation-topology-{}", tamper_id(tamper)),
            ..AuthorizationOptions::default()
        };
        let mut fixture = RuntimeFixture::new(&options);
        let exchange = fixture.exchange(Some(tamper));
        assert_eq!(exchange.client, Err(ObserverError::Transport));
        assert_eq!(exchange.server, Err(BridgeError::Authentication));
    }
}

fn tamper_id(value: Tamper) -> &'static str {
    match value {
        Tamper::Body => "body",
        Tamper::Signature => "signature",
        Tamper::Deployment => "deployment",
        Tamper::Audience => "audience",
        Tamper::Future => "future",
        Tamper::None => "none",
    }
}
