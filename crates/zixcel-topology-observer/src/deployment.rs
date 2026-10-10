use std::{
    path::{Path, PathBuf},
    time::Duration,
};

use crowsi_local_control_bridge::{LocalControlServer, PrivateUnixListener, SystemTrustedClock};
use serde::{Deserialize, de::DeserializeOwned};

use crate::{
    ObserverError, ResponseReplayStore, TOPOLOGY_WORKLOAD_ID, TopologyObservationHandler,
    ZixcelResponseTrust,
    identity_status_deployment::{IdentityStatusDeploymentV2, compose_bridge},
    secure_file::{self, FilePolicy},
};

#[cfg(test)]
mod legacy_tests;
#[cfg(test)]
mod tests;

pub type TopologyObserverServer =
    LocalControlServer<SystemTrustedClock, TopologyObservationHandler<SystemTrustedClock>>;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DeploymentV3 {
    pub(crate) schema: String,
    pub(crate) socket_path: PathBuf,
    pub(crate) bridge_state_path: PathBuf,
    pub(crate) response_state_path: PathBuf,
    pub(crate) response_trust_path: PathBuf,
    pub(crate) request_url: String,
    pub(crate) pa_public_key_hex: String,
    pub(crate) caller_uid: u32,
    pub(crate) caller_gid: u32,
    pub(crate) workload_id: String,
    pub(crate) client_executable_sha256: String,
    pub(crate) rate_limit_per_minute: u32,
    pub(crate) identity_status: IdentityStatusDeploymentV2,
}

/// Loads one closed deployment and composes the Crowsi authorization boundary.
///
/// # Errors
///
/// Rejects unsafe files, identities, state, clocks, or response trust.
pub fn load_server(path: &Path) -> Result<TopologyObserverServer, ObserverError> {
    let config: DeploymentV3 = read_policy_json(path, 16_384)?;
    if config.schema != "crowsi://topology-observer/deployment/v3" {
        return Err(ObserverError::Contract);
    }
    if config.workload_id != TOPOLOGY_WORKLOAD_ID {
        return Err(ObserverError::Contract);
    }
    let bridge = compose_bridge(&config)?;
    let handler = TopologyObservationHandler::new(
        ZixcelResponseTrust::load(&config.response_trust_path, &config.request_url)?,
        ResponseReplayStore::open(&config.response_state_path)?,
        SystemTrustedClock::new().map_err(|_| ObserverError::Time)?,
    );
    let socket =
        PrivateUnixListener::bind(config.socket_path).map_err(|_| ObserverError::Transport)?;
    Ok(LocalControlServer::new(
        socket,
        bridge,
        handler,
        Duration::from_secs(5),
    ))
}

fn read_policy_json<T: DeserializeOwned>(path: &Path, maximum: usize) -> Result<T, ObserverError> {
    decode_json(path, maximum, FilePolicy::ProvisionedPolicy)
}

/// Reads bounded JSON only from an absolute owner-only regular file.
///
/// # Errors
///
/// Rejects symlinks, broad permissions, wrong ownership, or oversized content.
pub fn read_owner_only_json<T: DeserializeOwned>(
    path: &Path,
    maximum: usize,
) -> Result<T, ObserverError> {
    decode_json(path, maximum, FilePolicy::OwnerOnly)
}

fn decode_json<T: DeserializeOwned>(
    path: &Path,
    maximum: usize,
    policy: FilePolicy,
) -> Result<T, ObserverError> {
    let bytes = secure_file::read(path, maximum, policy)?;
    serde_json::from_slice(&bytes).map_err(|_| ObserverError::Contract)
}
