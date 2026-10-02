mod routing;

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};

use tiny_http::{Header, Request, Response, Server, StatusCode};

use crate::authentication::ResponseSigner;

pub fn serve(database: PathBuf, address: SocketAddr) -> Result<(), String> {
    run(database, address, None)
}

pub fn serve_authenticated(
    database: PathBuf,
    address: SocketAddr,
    private_identity: &Path,
) -> Result<(), String> {
    if address.ip() != IpAddr::V4(Ipv4Addr::LOCALHOST) {
        return Err("authenticated topology API requires 127.0.0.1".to_owned());
    }
    run(
        database,
        address,
        Some(ResponseSigner::load(private_identity)?),
    )
}

fn run(
    database: PathBuf,
    address: SocketAddr,
    signer: Option<ResponseSigner>,
) -> Result<(), String> {
    if !address.ip().is_loopback() {
        return Err("topology API must bind to a loopback address".to_owned());
    }
    let server = Server::http(address).map_err(|error| error.to_string())?;
    for request in server.incoming_requests() {
        respond(request, &database, address, signer.as_ref())?;
    }
    Ok(())
}

fn respond(
    request: Request,
    database: &Path,
    address: SocketAddr,
    signer: Option<&ResponseSigner>,
) -> Result<(), String> {
    let protected = request.url().starts_with("/v1/");
    let nonce = header(&request, "X-Zixcel-Request-Nonce");
    let audience = header(&request, "X-Zixcel-Audience");
    if protected
        && signer.is_some_and(|value| {
            !audience.is_some_and(|audience| value.accepts_audience(audience)) || nonce.is_none()
        })
    {
        return send(
            request,
            401,
            routing::error_body("authenticated-request-required"),
            None,
        );
    }
    let method = request.method().as_str().to_owned();
    let path = request.url().to_owned();
    let (status, value) = routing::route(request.method(), &path, database);
    let body = serde_json::to_vec(&value).map_err(|error| error.to_string())?;
    let proof = if protected {
        signer
            .map(|value| {
                value.sign(
                    &method,
                    &format!("http://{address}{path}"),
                    nonce.unwrap_or_default(),
                    status,
                    &body,
                    crate::clock::epoch_seconds()?,
                )
            })
            .transpose()?
    } else {
        None
    };
    send(request, status, body, proof.as_ref())
}

fn send(
    request: Request,
    status: u16,
    body: impl Into<Vec<u8>>,
    proof: Option<&crate::authentication::SignedResponseHeaders>,
) -> Result<(), String> {
    let mut response = Response::from_data(body)
        .with_status_code(StatusCode(status))
        .with_header(json_header()?);
    if let Some(value) = proof {
        response.add_header(header_value("X-Zixcel-Proof", &value.proof_base64url)?);
        response.add_header(header_value(
            "X-Zixcel-Signature",
            &value.signature_base64url,
        )?);
        response.add_header(header_value("Cache-Control", "no-store")?);
    }
    request.respond(response).map_err(|error| error.to_string())
}

fn header<'a>(request: &'a Request, name: &'static str) -> Option<&'a str> {
    request
        .headers()
        .iter()
        .find(|value| value.field.equiv(name))
        .map(|value| value.value.as_str())
}

fn json_header() -> Result<Header, String> {
    header_value("Content-Type", "application/json; charset=utf-8")
}

fn header_value(name: &str, value: &str) -> Result<Header, String> {
    Header::from_bytes(name, value).map_err(|_| "could not create HTTP header".to_owned())
}

pub fn parse_loopback(value: &str) -> Result<SocketAddr, String> {
    let address: SocketAddr = value
        .parse()
        .map_err(|_| "invalid socket address".to_owned())?;
    if address.ip().is_loopback() {
        Ok(address)
    } else {
        Err("address must be loopback".to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::parse_loopback;

    #[test]
    fn rejects_public_bind_addresses() {
        assert!(parse_loopback("127.0.0.1:4211").is_ok());
        assert!(parse_loopback("0.0.0.0:4211").is_err());
    }
}
