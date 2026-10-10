use super::DeploymentV3;

#[test]
fn deployment_schema_fixes_the_identity_status_consumer_context() {
    let schema: serde_json::Value =
        serde_json::from_str(include_str!("../../schemas/deployment-v3.schema.json"))
            .expect("deployment schema");
    assert_eq!(
        schema["properties"]["identity_status"]["properties"]["audience"]["const"],
        "crowsi://topology-observer/current-status"
    );
    assert_eq!(
        schema["properties"]["identity_status"]["properties"]["service_id"]["const"],
        "service:crowsi"
    );
}

#[test]
fn legacy_v2_deployment_is_not_current() {
    let legacy = serde_json::json!({
        "schema": "crowsi://topology-observer/deployment/v2",
        "socket_path": "/run/crowsi/topology.sock",
        "bridge_state_path": "/var/lib/crowsi/bridge.sqlite3",
        "response_state_path": "/var/lib/crowsi/response.sqlite3",
        "response_trust_path": "/etc/crowsi/response.json",
        "request_url": "https://topology.invalid/v1",
        "pa_public_key_hex": "11".repeat(32),
        "caller_uid": 1000,
        "caller_gid": 1000,
        "workload_id": "spiffe://crowsi/local/coela-topology-client",
        "client_executable_sha256": format!("sha256:{}", "1".repeat(64)),
        "rate_limit_per_minute": 20,
        "identity_status": {
            "public_key_hex": "22".repeat(32),
            "key_id": "status-key:1",
            "issuer": "ihat://identity-authority",
            "audience": "crowsi://topology-observer/current-status",
            "service_id": "service:crowsi",
            "path": "/run/crowsi/current-status.json",
            "pairwise_subject": "pairwise:crowsi:topology",
            "device_id": "device:a",
            "device_proof_key_ref": "keyref:a"
        }
    });
    assert!(serde_json::from_value::<DeploymentV3>(legacy).is_err());
}

#[test]
fn current_deployment_requires_session_reference() {
    let missing = serde_json::json!({
        "schema": "crowsi://topology-observer/deployment/v3",
        "socket_path": "/run/crowsi/topology.sock",
        "bridge_state_path": "/var/lib/crowsi/bridge.sqlite3",
        "response_state_path": "/var/lib/crowsi/response.sqlite3",
        "response_trust_path": "/etc/crowsi/response.json",
        "request_url": "https://topology.invalid/v1",
        "pa_public_key_hex": "11".repeat(32),
        "caller_uid": 1000,
        "caller_gid": 1000,
        "workload_id": "spiffe://crowsi/local/coela-topology-client",
        "client_executable_sha256": format!("sha256:{}", "1".repeat(64)),
        "rate_limit_per_minute": 20,
        "identity_status": {
            "public_key_hex": "22".repeat(32),
            "key_id": "status-key:1",
            "issuer": "ihat://identity-authority",
            "audience": "crowsi://topology-observer/current-status",
            "service_id": "service:crowsi",
            "path": "/run/crowsi/current-status.json",
            "pairwise_subject": "pairwise:crowsi:topology",
            "device_id": "device:a",
            "device_proof_key_ref": "keyref:a"
        }
    });
    assert!(serde_json::from_value::<DeploymentV3>(missing).is_err());
}
