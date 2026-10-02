use std::collections::BTreeMap;
use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

use zixcel_topology_api::model::{
    ConnectionState, NodeKind, SCHEMA, TopologyDocument, TopologyNode,
};

fn node(state: ConnectionState, error_code: Option<&str>) -> TopologyNode {
    let observed = matches!(
        state,
        ConnectionState::Connected | ConnectionState::Degraded
    )
    .then(|| "2026-07-30T00:00:00.000Z".to_owned());
    TopologyNode {
        id: "service:example".to_owned(),
        label: "Example".to_owned(),
        kind: NodeKind::Service,
        status: "active".to_owned(),
        connection_state: state,
        source: "test".to_owned(),
        evidence: "declared".to_owned(),
        last_observed_at: observed,
        error_code: error_code.map(str::to_owned),
        attributes: BTreeMap::new(),
    }
}

fn document(node: TopologyNode) -> TopologyDocument {
    TopologyDocument {
        schema: SCHEMA.to_owned(),
        generated_at: "1".to_owned(),
        nodes: vec![node],
        edges: vec![],
    }
}

#[test]
fn disconnected_state_requires_safe_error_evidence() {
    assert!(
        document(node(ConnectionState::Disconnected, None))
            .validate()
            .is_err()
    );
    assert!(
        document(node(
            ConnectionState::Disconnected,
            Some("provider-not-connected")
        ))
        .validate()
        .is_ok()
    );
}

#[test]
fn sqlite_round_trip_and_connection_transitions_are_deterministic() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let path = std::env::temp_dir().join(format!("zixcel-topology-{unique}.sqlite3"));
    let mut database = zixcel_topology_api::store::open(&path).expect("open");
    let input = document(node(ConnectionState::Connected, None));
    zixcel_topology_api::store::replace(&mut database, &input).expect("replace");
    zixcel_topology_api::store::disconnect(&database, "service:example", "provider-not-connected")
        .expect("disconnect");
    let offline = zixcel_topology_api::store::read(&database).expect("read");
    assert_eq!(
        offline.nodes[0].connection_state,
        ConnectionState::Disconnected
    );
    zixcel_topology_api::store::connect(&database, "service:example").expect("connect");
    let online = zixcel_topology_api::store::read(&database).expect("read");
    assert_eq!(online.nodes[0].connection_state, ConnectionState::Connected);
    assert_eq!(online.nodes[0].error_code, None);
    drop(database);
    let read_only = zixcel_topology_api::store::open_read_only(&path).expect("read-only open");
    assert_eq!(
        zixcel_topology_api::store::read(&read_only)
            .expect("read-only query")
            .nodes
            .len(),
        1
    );
    drop(read_only);
    fs::remove_file(path).expect("remove database");
}
