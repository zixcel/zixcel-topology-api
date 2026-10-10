use std::path::PathBuf;

use crowsi_local_control_bridge::{
    BridgeTrust, CurrentStatusBinding, DurableSecurityStore, IdentityStatusTrust,
    LocalControlBridge, SystemTrustedClock,
};
use serde::Deserialize;

use crate::{
    ObserverError,
    deployment::DeploymentV3,
    secure_file::{self, FilePolicy},
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct IdentityStatusDeploymentV2 {
    pub(crate) public_key_hex: String,
    pub(crate) key_id: String,
    pub(crate) issuer: String,
    pub(crate) audience: String,
    pub(crate) service_id: String,
    pub(crate) path: PathBuf,
    pub(crate) pairwise_subject: String,
    pub(crate) device_id: String,
    pub(crate) device_proof_key_ref: String,
    pub(crate) session_ref: String,
}

pub(crate) fn compose_bridge(
    config: &DeploymentV3,
) -> Result<LocalControlBridge<SystemTrustedClock>, ObserverError> {
    if config.identity_status.audience != "crowsi://topology-observer/current-status"
        || config.identity_status.service_id != "service:crowsi"
    {
        return Err(ObserverError::Contract);
    }
    let pa = decode_key(&config.pa_public_key_hex)?;
    let status_key = decode_key(&config.identity_status.public_key_hex)?;
    let status_trust = IdentityStatusTrust::new(
        status_key,
        &config.identity_status.key_id,
        &config.identity_status.issuer,
        &config.identity_status.audience,
        &config.identity_status.service_id,
    )
    .map_err(|_| ObserverError::Contract)?;
    let trust = BridgeTrust::new(
        pa,
        config.caller_uid,
        config.caller_gid,
        &config.workload_id,
        &config.client_executable_sha256,
        status_trust,
    )
    .map_err(|_| ObserverError::Contract)?;
    let store = DurableSecurityStore::open(&config.bridge_state_path, config.rate_limit_per_minute)
        .map_err(|_| ObserverError::Storage)?;
    let clock = SystemTrustedClock::new().map_err(|_| ObserverError::Time)?;
    let mut bridge = LocalControlBridge::new(trust, store, clock);
    let wire = secure_file::read(&config.identity_status.path, 16_384, FilePolicy::OwnerOnly)?;
    let binding = CurrentStatusBinding::new(
        &config.identity_status.pairwise_subject,
        &config.identity_status.service_id,
        &config.identity_status.device_id,
        &config.identity_status.device_proof_key_ref,
        &config.identity_status.session_ref,
    )
    .map_err(|_| ObserverError::Contract)?;
    bridge
        .apply_current_device_status(&wire, &binding)
        .map_err(|_| ObserverError::Authorization)?;
    Ok(bridge)
}

fn decode_key(value: &str) -> Result<[u8; 32], ObserverError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(ObserverError::Contract);
    }
    hex::decode(value)
        .map_err(|_| ObserverError::Contract)?
        .try_into()
        .map_err(|_| ObserverError::Contract)
}
