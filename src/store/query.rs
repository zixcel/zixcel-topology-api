use rusqlite::Connection;

use crate::model::{TopologyDocument, TopologyEdge, TopologyNode};

use super::text;

pub fn read(connection: &Connection) -> Result<TopologyDocument, String> {
    let (schema, generated_at) = connection
        .query_row(
            "SELECT schema,generated_at FROM topology_meta WHERE id=1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(text)?;
    let nodes = read_nodes(connection)?;
    let edges = read_edges(connection)?;
    Ok(TopologyDocument {
        schema,
        generated_at,
        nodes,
        edges,
    })
}

fn read_nodes(connection: &Connection) -> Result<Vec<TopologyNode>, String> {
    let mut statement = connection
        .prepare(
            "SELECT id,label,kind,status,connection_state,source,evidence,\
             last_observed_at,error_code,attributes_json \
             FROM topology_nodes ORDER BY kind,label",
        )
        .map_err(text)?;
    statement
        .query_map([], |row| {
            Ok(TopologyNode {
                id: row.get(0)?,
                label: row.get(1)?,
                kind: from_json(row.get::<_, String>(2)?)?,
                status: row.get(3)?,
                connection_state: from_json(row.get::<_, String>(4)?)?,
                source: row.get(5)?,
                evidence: row.get(6)?,
                last_observed_at: row.get(7)?,
                error_code: row.get(8)?,
                attributes: from_json(row.get::<_, String>(9)?)?,
            })
        })
        .map_err(text)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(text)
}

fn read_edges(connection: &Connection) -> Result<Vec<TopologyEdge>, String> {
    let mut statement = connection
        .prepare(
            "SELECT id,source_node_id,target_node_id,relation,status \
             FROM topology_edges ORDER BY id",
        )
        .map_err(text)?;
    statement
        .query_map([], |row| {
            Ok(TopologyEdge {
                id: row.get(0)?,
                source_node_id: row.get(1)?,
                target_node_id: row.get(2)?,
                relation: row.get(3)?,
                status: row.get(4)?,
            })
        })
        .map_err(text)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(text)
}

fn from_json<T: serde::de::DeserializeOwned>(value: String) -> rusqlite::Result<T> {
    serde_json::from_str(&value).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(
            value.len(),
            rusqlite::types::Type::Text,
            Box::new(error),
        )
    })
}
