use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};

use base64::Engine;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde_json::Value;
use tempfile::TempDir;
use zixcel_topology_api::authentication::{
    IdentityPolicy, ResponseSigner, generate_identity, signed_message,
};

const NOW: u64 = 1_785_283_200;

#[test]
fn generated_identity_signs_a_nonce_bound_response() {
    let root = private_root();
    let private = root.path().join("signing-key.json");
    let trust = root.path().join("trust-bundle.json");
    generate_identity(&private, &trust, &policy()).unwrap();

    let signer = ResponseSigner::load(&private).unwrap();
    let body = br#"{"schema":"zixcel://topology/api-response/v1"}"#;
    let nonce = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([1_u8; 32]);
    let headers = signer
        .sign(
            "GET",
            "http://127.0.0.1:4211/v1/topology",
            &nonce,
            200,
            body,
            NOW,
        )
        .unwrap();

    let bundle: Value = serde_json::from_slice(&fs::read(&trust).unwrap()).unwrap();
    let public = decode_32(bundle["public_key_base64url"].as_str().unwrap());
    let verifying = VerifyingKey::from_bytes(&public).unwrap();
    let proof = decode(&headers.proof_base64url);
    let signature = Signature::from_slice(&decode(&headers.signature_base64url)).unwrap();
    verifying
        .verify(&signed_message(&proof, body), &signature)
        .unwrap();
    let value: Value = serde_json::from_slice(&proof).unwrap();
    assert_eq!(value["request_nonce"], nonce);
    assert_eq!(value["audience"], "example-client");
    assert_eq!(bundle["audience"], "example-client");
    assert!(signer.accepts_audience("example-client"));
    assert!(!signer.accepts_audience("different-client"));
    assert!(!signer.accepts_audience(""));
    assert_eq!(value["deployment_id"], "zixcel-topology-api-local");
}

#[test]
fn private_identity_is_owner_only_and_never_overwritten() {
    let root = private_root();
    let private = root.path().join("signing-key.json");
    let trust = root.path().join("trust-bundle.json");
    generate_identity(&private, &trust, &policy()).unwrap();
    assert_eq!(fs::metadata(&private).unwrap().mode() & 0o777, 0o600);
    assert!(generate_identity(&private, &trust, &policy()).is_err());
}

#[test]
fn signer_rejects_open_or_malformed_request_values() {
    let root = private_root();
    let private = root.path().join("signing-key.json");
    let trust = root.path().join("trust-bundle.json");
    generate_identity(&private, &trust, &policy()).unwrap();
    let signer = ResponseSigner::load(&private).unwrap();
    assert!(
        signer
            .sign(
                "POST",
                "http://127.0.0.1:4211/v1/topology",
                "bad",
                200,
                b"{}",
                NOW
            )
            .is_err()
    );
}

#[test]
fn signature_domain_claims_response_authenticity_only() {
    let message = signed_message(b"{}", b"{}");
    assert!(message.starts_with(b"ZIXCEL-TOPOLOGY-RESPONSE-AUTHENTICITY-V1\0"));
    assert!(!message.windows(6).any(|value| value == b"CROWSI"));
}

fn private_root() -> TempDir {
    let root = tempfile::tempdir().unwrap();
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
    root
}

fn policy() -> IdentityPolicy {
    IdentityPolicy {
        audience: "example-client".into(),
        security_domain: "example-domain".into(),
        deployment_id: "zixcel-topology-api-local".into(),
    }
}

fn decode(value: &str) -> Vec<u8> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(value)
        .unwrap()
}

fn decode_32(value: &str) -> [u8; 32] {
    decode(value).try_into().unwrap()
}

#[test]
fn invalid_caller_audience_cannot_create_an_identity() {
    let root = private_root();
    let private = root.path().join("invalid-private.json");
    let trust = root.path().join("invalid-trust.json");
    let mut policy = policy();
    policy.audience = "bad\nclient".into();
    assert!(generate_identity(&private, &trust, &policy).is_err());
    assert!(!private.exists());
    assert!(!trust.exists());
}
