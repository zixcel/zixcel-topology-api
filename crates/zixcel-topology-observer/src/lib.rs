#![forbid(unsafe_code)]
#![doc = "Crowsi-authorized, replay-safe local Zixcel topology observation."]

mod canonical;
mod client;
mod deployment;
mod error;
mod handler;
mod http;
mod identity_status_deployment;
mod model;
mod proof_wire;
mod replay;
mod response;
mod secure_file;
mod server_peer;
mod socket_path;
mod trust;

pub use canonical::{canonical_operation, operation_body_sha256, sha256_digest};
pub use client::TopologyObservationClient;
pub use deployment::{TopologyObserverServer, load_server, read_owner_only_json};
pub use error::ObserverError;
pub use handler::TopologyObservationHandler;
pub use model::{
    CrowsiObservationEvidenceV1, ObservationBundleV1, ObservationReceiptV1,
    TopologyObservationRequestV1, VerifiedResponseEvidenceV1,
};
pub use replay::ResponseReplayStore;
pub use trust::ZixcelResponseTrust;

pub const OBSERVATION_PURPOSE: &str = "operational-topology-observation";
pub const TOPOLOGY_RESOURCE: &str = "zixcel://topology/v1/topology";
pub const TOPOLOGY_WORKLOAD_ID: &str = "spiffe://crowsi/local/coela-topology-client";
