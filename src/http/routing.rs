use std::path::Path;

use serde_json::{Value, json};
use tiny_http::Method;

use crate::model::{ConnectionState, TopologyDocument};

pub(super) fn route(method: &Method, url: &str, database: &Path) -> (u16, Value) {
    if method != &Method::Get {
        return (405, error_value("method-not-allowed"));
    }
    let document =
        match crate::store::open_read_only(database).and_then(|db| crate::store::read(&db)) {
            Ok(value) => value,
            Err(_) => return (503, error_value("topology-store-unavailable")),
        };
    match url.split('?').next().unwrap_or(url) {
        "/health" => (
            200,
            json!({
                "schema": "zixcel://topology/health/v1",
                "status": "healthy",
                "node_count": document.nodes.len()
            }),
        ),
        "/v1/topology" => (200, topology_response(document)),
        path if path.starts_with("/v1/nodes/") => {
            match crate::url_path::decode_segment(path.trim_start_matches("/v1/nodes/")) {
                Ok(id) => node_response(&document, &id),
                Err(()) => (400, error_value("invalid-node-id")),
            }
        }
        _ => (404, error_value("route-not-found")),
    }
}

fn topology_response(document: TopologyDocument) -> Value {
    let disconnected = document
        .nodes
        .iter()
        .filter(|node| node.connection_state == ConnectionState::Disconnected)
        .count();
    json!({
        "schema": "zixcel://topology/api-response/v1",
        "summary": {
            "node_count": document.nodes.len(),
            "edge_count": document.edges.len(),
            "disconnected_count": disconnected
        },
        "document": document
    })
}

fn node_response(document: &TopologyDocument, id: &str) -> (u16, Value) {
    let Some(node) = document.nodes.iter().find(|node| node.id == id) else {
        return (404, error_value("node-not-found"));
    };
    let edges: Vec<_> = document
        .edges
        .iter()
        .filter(|edge| edge.source_node_id == id || edge.target_node_id == id)
        .cloned()
        .collect();
    let related_ids: Vec<_> = edges
        .iter()
        .map(|edge| {
            if edge.source_node_id == id {
                &edge.target_node_id
            } else {
                &edge.source_node_id
            }
        })
        .collect();
    let related: Vec<_> = document
        .nodes
        .iter()
        .filter(|item| related_ids.contains(&&item.id))
        .cloned()
        .collect();
    (
        200,
        json!({
            "schema": "zixcel://topology/node-detail/v1",
            "node": node,
            "edges": edges,
            "related_nodes": related
        }),
    )
}

pub(super) fn error_body(code: &str) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "schema": "zixcel://topology/error/v1",
        "error_code": code
    }))
    .unwrap_or_else(|_| b"{\"error_code\":\"serialization-failed\"}".to_vec())
}

fn error_value(code: &str) -> Value {
    json!({ "schema": "zixcel://topology/error/v1", "error_code": code })
}
