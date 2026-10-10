use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    time::Duration,
};

use crate::{ObserverError, TopologyObservationRequestV1};

pub(crate) struct WireResponse {
    pub status: u16,
    pub body: Vec<u8>,
    pub proof: String,
    pub signature: String,
}

pub(crate) fn exchange(
    request: &TopologyObservationRequestV1,
    audience: &str,
) -> Result<WireResponse, ObserverError> {
    let (address, path) = endpoint(&request.request_url)?;
    let timeout = Duration::from_secs(3);
    let mut stream =
        TcpStream::connect_timeout(&address, timeout).map_err(|_| ObserverError::Transport)?;
    stream
        .set_read_timeout(Some(timeout))
        .and_then(|()| stream.set_write_timeout(Some(timeout)))
        .map_err(|_| ObserverError::Transport)?;
    let message = format!(
        "GET {path} HTTP/1.1\r\nHost: {address}\r\nAccept: application/json\r\n\
         X-Zixcel-Audience: {audience}\r\nX-Zixcel-Request-Nonce: {}\r\n\
         Connection: close\r\n\r\n",
        request.request_nonce
    );
    stream
        .write_all(message.as_bytes())
        .map_err(|_| ObserverError::Transport)?;
    let limit = u64::from(request.maximum_response_bytes) + 16_385;
    let mut bytes = Vec::new();
    stream
        .take(limit)
        .read_to_end(&mut bytes)
        .map_err(|_| ObserverError::Transport)?;
    if u64::try_from(bytes.len()).map_err(|_| ObserverError::Contract)? == limit {
        return Err(ObserverError::Contract);
    }
    parse(
        &bytes,
        usize::try_from(request.maximum_response_bytes).unwrap_or(0),
    )
}

fn endpoint(url: &str) -> Result<(SocketAddr, &str), ObserverError> {
    let suffix = url
        .strip_prefix("http://127.0.0.1:")
        .ok_or(ObserverError::Contract)?;
    let (port, path) = suffix.split_once('/').ok_or(ObserverError::Contract)?;
    let port: u16 = port.parse().map_err(|_| ObserverError::Contract)?;
    let address = SocketAddr::from(([127, 0, 0, 1], port));
    Ok((address, &url[url.len() - path.len() - 1..]))
}

fn parse(bytes: &[u8], maximum: usize) -> Result<WireResponse, ObserverError> {
    let split = bytes
        .windows(4)
        .position(|item| item == b"\r\n\r\n")
        .ok_or(ObserverError::Contract)?;
    if split > 16_380 {
        return Err(ObserverError::Contract);
    }
    let head = std::str::from_utf8(&bytes[..split]).map_err(|_| ObserverError::Contract)?;
    let body = bytes[split + 4..].to_vec();
    let mut lines = head.split("\r\n");
    let status = status(lines.next().ok_or(ObserverError::Contract)?)?;
    let mut content_type = None;
    let mut content_length = None;
    let mut proof = None;
    let mut signature = None;
    for line in lines {
        let (name, value) = line.split_once(':').ok_or(ObserverError::Contract)?;
        match name.to_ascii_lowercase().as_str() {
            "content-type" => unique(&mut content_type, value.trim())?,
            "content-length" => unique(&mut content_length, value.trim())?,
            "x-zixcel-proof" => unique(&mut proof, value.trim())?,
            "x-zixcel-signature" => unique(&mut signature, value.trim())?,
            "transfer-encoding" => return Err(ObserverError::Contract),
            _ => {}
        }
    }
    let length = content_length
        .ok_or(ObserverError::Contract)?
        .parse::<usize>()
        .map_err(|_| ObserverError::Contract)?;
    if status != 200
        || length != body.len()
        || body.len() < 2
        || body.len() > maximum
        || !content_type
            .is_some_and(|value| value.to_ascii_lowercase().starts_with("application/json"))
    {
        return Err(ObserverError::Contract);
    }
    Ok(WireResponse {
        status,
        body,
        proof: proof.ok_or(ObserverError::ResponseAuthenticity)?.into(),
        signature: signature.ok_or(ObserverError::ResponseAuthenticity)?.into(),
    })
}

fn unique<'a>(slot: &mut Option<&'a str>, value: &'a str) -> Result<(), ObserverError> {
    if slot.replace(value).is_some() || value.is_empty() {
        return Err(ObserverError::Contract);
    }
    Ok(())
}

fn status(value: &str) -> Result<u16, ObserverError> {
    let mut parts = value.split_ascii_whitespace();
    if !matches!(parts.next(), Some("HTTP/1.1" | "HTTP/1.0")) {
        return Err(ObserverError::Contract);
    }
    parts
        .next()
        .ok_or(ObserverError::Contract)?
        .parse()
        .map_err(|_| ObserverError::Contract)
}
