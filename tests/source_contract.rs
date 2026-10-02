use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use zixcel_topology_api::source_contract::read_bytes;

#[derive(Serialize)]
struct Payload<'a> {
    catalog_as_of: &'a str,
    nodes: &'a [Value],
    edges: &'a [Value],
}

#[test]
fn accepts_a_digest_bound_closed_source() {
    let bytes = source_bytes(false, false);
    let document = read_bytes(&bytes).expect("valid source");
    assert_eq!(document.nodes[0].id, "service:nerp");
}

#[test]
fn rejects_unknown_fields_digest_changes_and_platform_paths() {
    let unknown = source_bytes(true, false);
    assert!(
        read_bytes(&unknown)
            .unwrap_err()
            .contains("closed JSON contract")
    );
    let mut tampered: Value = serde_json::from_slice(&source_bytes(false, false)).unwrap();
    tampered["nodes"][0]["label"] = json!("tampered");
    assert!(
        read_bytes(&serde_json::to_vec(&tampered).unwrap())
            .unwrap_err()
            .contains("digest")
    );
    let path = source_bytes(false, true);
    assert!(read_bytes(&path).unwrap_err().contains("platform path"));
}

#[test]
fn rejects_oversized_input_before_deserialization() {
    let oversized = vec![b' '; 1_048_577];
    assert!(read_bytes(&oversized).unwrap_err().contains("size"));
}

#[test]
fn database_rejects_relative_and_symlink_paths() {
    assert!(
        zixcel_topology_api::store::open(std::path::Path::new("state/topology.sqlite3"))
            .unwrap_err()
            .contains("absolute")
    );
    #[cfg(unix)]
    {
        let root = tempfile::tempdir().expect("temporary state");
        let target = root.path().join("target.sqlite3");
        std::fs::write(&target, []).expect("target");
        let link = root.path().join("link.sqlite3");
        std::os::unix::fs::symlink(&target, &link).expect("symlink");
        assert!(
            zixcel_topology_api::store::open(&link)
                .unwrap_err()
                .contains("physical file")
        );
    }
}

#[test]
fn whole_file_replacement_erases_legacy_source_bytes() {
    let root = tempfile::tempdir().expect("temporary state");
    let database = root.path().join("topology.sqlite3");
    let home_marker = ["/", "home", "/"].concat();
    std::fs::write(
        &database,
        format!(
            "local_path data/operations/repository-environment/managed-repositories {home_marker}legacy"
        ),
    )
    .expect("legacy bytes");
    let document = read_bytes(&source_bytes(false, false)).expect("safe source");
    zixcel_topology_api::store::replace_file(&database, &document).expect("atomic replacement");
    let bytes = std::fs::read(&database).expect("database bytes");
    let forbidden_values = [
        b"local_path".to_vec(),
        b"data/operations/repository-environment/managed-repositories".to_vec(),
        home_marker.as_bytes().to_vec(),
    ];
    for forbidden in &forbidden_values {
        assert!(
            !bytes
                .windows(forbidden.len())
                .any(|window| window == forbidden)
        );
    }
    let connection = zixcel_topology_api::store::open_read_only(&database).expect("read database");
    let exported = serde_json::to_string(
        &zixcel_topology_api::store::read(&connection).expect("stored topology"),
    )
    .expect("exported JSON");
    assert!(!exported.contains("local_path"));
    assert!(!exported.contains(&home_marker));
}

fn source_bytes(unknown: bool, platform_path: bool) -> Vec<u8> {
    let mut node = json!({
        "id": "service:nerp", "label": "NERP", "kind": "service", "status": "active",
        "connection_state": "unknown", "source": "catalog://service/nerp",
        "evidence": "canonical-declaration", "last_observed_at": null,
        "error_code": null, "attributes": {}
    });
    if unknown {
        node["unexpected"] = json!(true);
    }
    if platform_path {
        node["attributes"]["local_path"] = json!("/outside");
    }
    let nodes = vec![node];
    let edges = Vec::new();
    let catalog_as_of = "2026-08-03";
    let canonical = serde_json::to_value(Payload {
        catalog_as_of,
        nodes: &nodes,
        edges: &edges,
    })
    .expect("payload value");
    let digest = format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(&canonical).unwrap())
    );
    serde_json::to_vec(&json!({
        "schema": "zixcel://topology/source/v1", "payload_sha256": digest,
        "catalog_as_of": catalog_as_of, "nodes": nodes, "edges": edges
    }))
    .unwrap()
}

#[test]
fn producer_specific_schema_is_rejected_without_replacing_current_state() {
    let mut source: Value = serde_json::from_slice(&source_bytes(false, false)).unwrap();
    source["schema"] = json!("legacy-producer://topology-source/v1");
    assert!(read_bytes(&serde_json::to_vec(&source).unwrap()).is_err());
}
