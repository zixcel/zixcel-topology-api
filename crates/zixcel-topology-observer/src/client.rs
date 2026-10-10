use std::{
    io::{Read, Write},
    net::Shutdown,
    os::unix::net::UnixStream,
    path::Path,
    time::Duration,
};

use crate::{
    OBSERVATION_PURPOSE, ObservationBundleV1, ObservationReceiptV1, ObserverError,
    TOPOLOGY_RESOURCE, canonical_operation, server_peer::attest_server, sha256_digest,
    socket_path::connect_private,
};
use crowsi_local_control_bridge::BridgeAction;

pub struct TopologyObservationClient {
    timeout: Duration,
}

impl TopologyObservationClient {
    /// Creates a bounded native client.
    ///
    /// # Errors
    ///
    /// Rejects absent or excessive I/O deadlines.
    pub fn new(timeout: Duration) -> Result<Self, ObserverError> {
        if timeout.is_zero() || timeout > Duration::from_secs(30) {
            return Err(ObserverError::Contract);
        }
        Ok(Self { timeout })
    }

    /// Consumes one PA-issued operation bundle over the private Unix boundary.
    ///
    /// # Errors
    ///
    /// Rejects binding, framing, transport, or closed receipt failures.
    pub fn observe(
        &self,
        socket: &Path,
        bundle: &ObservationBundleV1,
    ) -> Result<ObservationReceiptV1, ObserverError> {
        validate_bundle(bundle)?;
        let mut stream = connect_private(socket)?;
        attest_server(&stream)?;
        stream
            .set_read_timeout(Some(self.timeout))
            .and_then(|()| stream.set_write_timeout(Some(self.timeout)))
            .map_err(|_| ObserverError::Transport)?;
        let authorization =
            serde_json::to_vec(&bundle.authorization).map_err(|_| ObserverError::Contract)?;
        let operation = canonical_operation(&bundle.operation)?;
        write_frame(&mut stream, &authorization)?;
        write_frame(&mut stream, &operation)?;
        stream
            .shutdown(Shutdown::Write)
            .map_err(|_| ObserverError::Transport)?;
        let receipt: ObservationReceiptV1 =
            serde_json::from_slice(&read_frame(&mut stream, 1_064_960)?)
                .map_err(|_| ObserverError::Contract)?;
        validate_receipt(&receipt, bundle)?;
        Ok(receipt)
    }
}

fn validate_bundle(value: &ObservationBundleV1) -> Result<(), ObserverError> {
    let request = &value.authorization.request;
    let operation = canonical_operation(&value.operation)?;
    let valid = value.schema == "crowsi://topology-observer/bundle/v1"
        && value.authorization.schema == "crowsi://local-control/ipc-envelope/v2"
        && request.action == BridgeAction::ObserveProvider
        && request.resource == TOPOLOGY_RESOURCE
        && request.purpose == OBSERVATION_PURPOSE
        && request.body_sha256 == sha256_digest(&operation)
        && value.authorization.authorization.document.request_id == request.request_id;
    valid.then_some(()).ok_or(ObserverError::Authorization)
}

fn validate_receipt(
    value: &ObservationReceiptV1,
    bundle: &ObservationBundleV1,
) -> Result<(), ObserverError> {
    let valid = value.schema == "crowsi://topology-observer/receipt/v1"
        && value.state == "verified"
        && value.crowsi.authorization_consumed
        && value.crowsi.kernel_peer_verified
        && value.crowsi.executable_digest_verified
        && value.crowsi.workload_binding_verified
        && value.crowsi.trusted_monotonic_replay_verified
        && value.response.request_url == bundle.operation.request_url
        && value.response.request_nonce == bundle.operation.request_nonce
        && value.response.response_status == 200;
    valid.then_some(()).ok_or(ObserverError::Authorization)
}

fn write_frame(stream: &mut UnixStream, value: &[u8]) -> Result<(), ObserverError> {
    let length = u32::try_from(value.len()).map_err(|_| ObserverError::Contract)?;
    stream
        .write_all(&length.to_be_bytes())
        .and_then(|()| stream.write_all(value))
        .map_err(|_| ObserverError::Transport)
}

fn read_frame(stream: &mut UnixStream, maximum: usize) -> Result<Vec<u8>, ObserverError> {
    let mut length = [0_u8; 4];
    stream
        .read_exact(&mut length)
        .map_err(|_| ObserverError::Transport)?;
    let length =
        usize::try_from(u32::from_be_bytes(length)).map_err(|_| ObserverError::Contract)?;
    if length == 0 || length > maximum {
        return Err(ObserverError::Contract);
    }
    let mut value = vec![0; length];
    stream
        .read_exact(&mut value)
        .map_err(|_| ObserverError::Transport)?;
    Ok(value)
}
