use std::collections::{BTreeMap, HashSet};

use serde::{Deserialize, Serialize};

pub const SCHEMA: &str = "zixcel://topology/document/v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum NodeKind {
    Service,
    Repository,
    GithubOrganization,
    DeploymentInstance,
    ExternalService,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ConnectionState {
    Connected,
    Degraded,
    Disconnected,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TopologyNode {
    pub id: String,
    pub label: String,
    pub kind: NodeKind,
    pub status: String,
    pub connection_state: ConnectionState,
    pub source: String,
    pub evidence: String,
    pub last_observed_at: Option<String>,
    pub error_code: Option<String>,
    #[serde(default)]
    pub attributes: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TopologyEdge {
    pub id: String,
    pub source_node_id: String,
    pub target_node_id: String,
    pub relation: String,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TopologyDocument {
    pub schema: String,
    pub generated_at: String,
    pub nodes: Vec<TopologyNode>,
    pub edges: Vec<TopologyEdge>,
}

impl TopologyDocument {
    pub fn validate(&self) -> Result<(), String> {
        if self.schema != SCHEMA {
            return Err(format!("schema must be {SCHEMA}"));
        }
        let ids: HashSet<_> = self.nodes.iter().map(|node| node.id.as_str()).collect();
        if ids.len() != self.nodes.len() {
            return Err("node ids must be unique".to_owned());
        }
        for node in &self.nodes {
            valid_id(&node.id)?;
            if node.connection_state == ConnectionState::Disconnected && node.error_code.is_none() {
                return Err(format!(
                    "{}: disconnected nodes require error_code",
                    node.id
                ));
            }
            if matches!(
                node.connection_state,
                ConnectionState::Connected | ConnectionState::Degraded
            ) && node.last_observed_at.is_none()
            {
                return Err(format!(
                    "{}: observed nodes require last_observed_at",
                    node.id
                ));
            }
        }
        let mut edge_ids = HashSet::new();
        for edge in &self.edges {
            valid_id(&edge.id)?;
            if !edge_ids.insert(edge.id.as_str()) {
                return Err("edge ids must be unique".to_owned());
            }
            if !ids.contains(edge.source_node_id.as_str())
                || !ids.contains(edge.target_node_id.as_str())
            {
                return Err(format!("{}: edge references an unknown node", edge.id));
            }
        }
        Ok(())
    }
}

fn valid_id(value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > 240
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/')
        })
    {
        return Err(format!("{value}: invalid identifier"));
    }
    Ok(())
}
