PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS topology_meta (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  schema TEXT NOT NULL,
  generated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS topology_nodes (
  id TEXT PRIMARY KEY,
  label TEXT NOT NULL,
  kind TEXT NOT NULL,
  status TEXT NOT NULL,
  connection_state TEXT NOT NULL,
  source TEXT NOT NULL,
  evidence TEXT NOT NULL,
  last_observed_at TEXT,
  error_code TEXT,
  attributes_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS topology_edges (
  id TEXT PRIMARY KEY,
  source_node_id TEXT NOT NULL REFERENCES topology_nodes(id),
  target_node_id TEXT NOT NULL REFERENCES topology_nodes(id),
  relation TEXT NOT NULL,
  status TEXT NOT NULL
);
