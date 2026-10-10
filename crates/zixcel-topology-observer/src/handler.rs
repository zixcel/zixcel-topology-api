use std::{
    io::{Read, Write},
    os::unix::net::UnixStream,
};

use crowsi_local_control_bridge::{
    AuthorizedOperationHandler, BridgeAction, BridgeError, DispatchTicket, TrustedClock,
};

use crate::{
    OBSERVATION_PURPOSE, ObserverError, ResponseReplayStore, TOPOLOGY_RESOURCE,
    TopologyObservationRequestV1, ZixcelResponseTrust, canonical_operation, http, response,
    sha256_digest,
};

pub struct TopologyObservationHandler<C> {
    trust: ZixcelResponseTrust,
    replay: ResponseReplayStore,
    clock: C,
}

impl<C: TrustedClock> TopologyObservationHandler<C> {
    #[must_use]
    pub const fn new(trust: ZixcelResponseTrust, replay: ResponseReplayStore, clock: C) -> Self {
        Self {
            trust,
            replay,
            clock,
        }
    }

    fn observe(
        &mut self,
        ticket: &DispatchTicket,
        stream: &mut UnixStream,
    ) -> Result<(), ObserverError> {
        let bytes = read_frame(stream, 4_096)?;
        if sha256_digest(&bytes) != ticket.body_sha256 {
            return Err(ObserverError::Authorization);
        }
        let request: TopologyObservationRequestV1 =
            serde_json::from_slice(&bytes).map_err(|_| ObserverError::Contract)?;
        validate(ticket, &request, &self.trust)?;
        require_eof(stream)?;
        let wire = http::exchange(&request, &self.trust.audience)?;
        let receipt = response::verify(
            wire,
            &request,
            ticket,
            &self.trust,
            &mut self.replay,
            &self.clock,
        )?;
        let encoded = serde_json::to_vec(&receipt).map_err(|_| ObserverError::Contract)?;
        write_frame(stream, &encoded)
    }
}

impl<C: TrustedClock> AuthorizedOperationHandler for TopologyObservationHandler<C> {
    fn handle(
        &mut self,
        ticket: DispatchTicket,
        stream: &mut UnixStream,
    ) -> Result<(), BridgeError> {
        self.observe(&ticket, stream).map_err(map_error)
    }
}

fn validate(
    ticket: &DispatchTicket,
    request: &TopologyObservationRequestV1,
    trust: &ZixcelResponseTrust,
) -> Result<(), ObserverError> {
    let nonce = base64::Engine::decode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        &request.request_nonce,
    )
    .map_err(|_| ObserverError::Contract)?;
    let valid = ticket.action == BridgeAction::ObserveProvider
        && ticket.resource == TOPOLOGY_RESOURCE
        && ticket.purpose == OBSERVATION_PURPOSE
        && request.schema == "crowsi://topology-observer/request/v1"
        && request.request_url == trust.request_url
        && nonce.len() == 32
        && request.request_nonce
            == base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, &nonce)
        && (2..=1_048_576).contains(&request.maximum_response_bytes)
        && canonical_operation(request)
            .is_ok_and(|value| sha256_digest(&value) == ticket.body_sha256);
    valid.then_some(()).ok_or(ObserverError::Authorization)
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

fn write_frame(stream: &mut UnixStream, value: &[u8]) -> Result<(), ObserverError> {
    let length = u32::try_from(value.len()).map_err(|_| ObserverError::Contract)?;
    stream
        .write_all(&length.to_be_bytes())
        .and_then(|()| stream.write_all(value))
        .map_err(|_| ObserverError::Transport)
}

fn require_eof(stream: &mut UnixStream) -> Result<(), ObserverError> {
    let mut trailing = [0_u8; 1];
    match stream.read(&mut trailing) {
        Ok(0) => Ok(()),
        Ok(_) => Err(ObserverError::Contract),
        Err(_) => Err(ObserverError::Transport),
    }
}

fn map_error(value: ObserverError) -> BridgeError {
    match value {
        ObserverError::Contract => BridgeError::Contract,
        ObserverError::Authorization => BridgeError::Binding,
        ObserverError::Transport => BridgeError::Transport,
        ObserverError::ResponseAuthenticity => BridgeError::Authentication,
        ObserverError::Time => BridgeError::Time,
        ObserverError::Replay => BridgeError::Replay,
        ObserverError::Storage => BridgeError::Storage,
    }
}
