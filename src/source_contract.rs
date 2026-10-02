//! Validates the bounded provider-owned topology source contract before topology state is replaced.

use crate::model::{ConnectionState, TopologyDocument, TopologyEdge, TopologyNode};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::Read;

const SCHEMA: &str = "zixcel://topology/source/v1";
const MAX_BYTES: u64 = 1_048_576;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TopologySource {
    schema: String,
    payload_sha256: String,
    catalog_as_of: String,
    nodes: Vec<TopologyNode>,
    edges: Vec<TopologyEdge>,
}

#[derive(Serialize)]
struct SourcePayload<'a> {
    catalog_as_of: &'a str,
    nodes: &'a [TopologyNode],
    edges: &'a [TopologyEdge],
}

pub fn read<R: Read>(reader: R) -> Result<TopologyDocument, String> {
    let mut bytes = Vec::new();
    reader
        .take(MAX_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    read_bytes(&bytes)
}

pub fn read_bytes(bytes: &[u8]) -> Result<TopologyDocument, String> {
    if bytes.is_empty() || bytes.len() as u64 > MAX_BYTES {
        return Err("topology source size is outside the accepted boundary".into());
    }
    let source: TopologySource = serde_json::from_slice(bytes)
        .map_err(|_| "topology source is not the closed JSON contract".to_owned())?;
    if source.schema != SCHEMA || !valid_digest(&source.payload_sha256) {
        return Err("topology source authority or digest is invalid".into());
    }
    if source.nodes.len() > 5_000
        || source.edges.len() > 10_000
        || !valid_text(&source.catalog_as_of, 64, false)
    {
        return Err("topology source collections or timestamp are invalid".into());
    }
    reject_path_metadata(&source.nodes)?;
    let payload_value = serde_json::to_value(SourcePayload {
        catalog_as_of: &source.catalog_as_of,
        nodes: &source.nodes,
        edges: &source.edges,
    })
    .map_err(|error| error.to_string())?;
    let payload = serde_json::to_vec(&payload_value).map_err(|error| error.to_string())?;
    if format!("{:x}", Sha256::digest(payload)) != source.payload_sha256 {
        return Err("topology source digest differs".into());
    }
    let document = TopologyDocument {
        schema: crate::model::SCHEMA.into(),
        generated_at: crate::clock::canonical_now()?,
        nodes: source.nodes,
        edges: source.edges,
    };
    document.validate()?;
    Ok(document)
}

fn reject_path_metadata(nodes: &[TopologyNode]) -> Result<(), String> {
    for node in nodes {
        if !node.source.starts_with("catalog://")
            || !valid_text(&node.source, 240, false)
            || !valid_text(&node.label, 240, false)
            || !valid_text(&node.status, 64, false)
            || !valid_text(&node.evidence, 240, false)
            || node.attributes.len() > 64
        {
            return Err("topology source contains a non-logical source reference".into());
        }
        if matches!(
            node.connection_state,
            ConnectionState::Connected | ConnectionState::Degraded
        ) || node.last_observed_at.is_some()
        {
            return Err("topology source may not claim runtime observation".into());
        }
        for (key, value) in &node.attributes {
            let drive_path = value.as_bytes().get(1) == Some(&b':')
                && value
                    .as_bytes()
                    .get(2)
                    .is_some_and(|byte| matches!(byte, b'/' | b'\\'));
            if !valid_attribute_key(key)
                || !valid_text(value, 240, true)
                || matches!(
                    key.as_str(),
                    "path" | "local_path" | "root_path" | "source_path"
                )
                || value.starts_with('/')
                || drive_path
            {
                return Err("topology source contains platform path metadata".into());
            }
        }
    }
    Ok(())
}

fn valid_attribute_key(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b':' | b'-'))
}

fn valid_text(value: &str, maximum: usize, empty: bool) -> bool {
    (empty || !value.is_empty())
        && value.encode_utf16().count() <= maximum
        && !value.chars().any(char::is_control)
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}
