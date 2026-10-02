use rusqlite::{Connection, params};

use crate::model::TopologyDocument;

use super::{json, text};

pub fn replace(connection: &mut Connection, document: &TopologyDocument) -> Result<(), String> {
    document.validate()?;
    let transaction = connection
        .transaction()
        .map_err(|error| error.to_string())?;
    transaction
        .execute("DELETE FROM topology_edges", [])
        .map_err(text)?;
    transaction
        .execute("DELETE FROM topology_nodes", [])
        .map_err(text)?;
    for node in &document.nodes {
        transaction
            .execute(
                "INSERT INTO topology_nodes VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
                params![
                    node.id,
                    node.label,
                    json(&node.kind)?,
                    node.status,
                    json(&node.connection_state)?,
                    node.source,
                    node.evidence,
                    node.last_observed_at,
                    node.error_code,
                    json(&node.attributes)?
                ],
            )
            .map_err(text)?;
    }
    for edge in &document.edges {
        transaction
            .execute(
                "INSERT INTO topology_edges VALUES (?1,?2,?3,?4,?5)",
                params![
                    edge.id,
                    edge.source_node_id,
                    edge.target_node_id,
                    edge.relation,
                    edge.status
                ],
            )
            .map_err(text)?;
    }
    transaction
        .execute(
            "INSERT OR REPLACE INTO topology_meta(id,schema,generated_at) VALUES(1,?1,?2)",
            params![document.schema, document.generated_at],
        )
        .map_err(text)?;
    transaction.commit().map_err(text)
}

pub fn disconnect(connection: &Connection, id: &str, code: &str) -> Result<(), String> {
    let changed = connection
        .execute(
            "UPDATE topology_nodes SET connection_state='\"disconnected\"',error_code=?2,\
             last_observed_at=NULL WHERE id=?1",
            params![id, code],
        )
        .map_err(text)?;
    exactly_one(changed, id)
}

pub fn connect(connection: &Connection, id: &str) -> Result<(), String> {
    let observed_at = crate::clock::canonical_now()?;
    let changed = connection
        .execute(
            "UPDATE topology_nodes SET connection_state='\"connected\"',error_code=NULL,\
             evidence='live-loopback',last_observed_at=?2 WHERE id=?1",
            params![id, observed_at],
        )
        .map_err(text)?;
    exactly_one(changed, id)
}

fn exactly_one(changed: usize, id: &str) -> Result<(), String> {
    if changed == 1 {
        Ok(())
    } else {
        Err(format!("node not found: {id}"))
    }
}
