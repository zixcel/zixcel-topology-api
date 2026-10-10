use std::{
    fs,
    io::{Read, Write},
    net::TcpListener,
    os::unix::fs::PermissionsExt,
    path::Path,
    thread,
    time::{SystemTime, UNIX_EPOCH},
};

use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use serde_json::json;
use zixcel_topology_observer::sha256_digest;
const DOMAIN: &[u8] = b"ZIXCEL-TOPOLOGY-RESPONSE-AUTHENTICITY-V1\0";

#[derive(Clone, Copy, Default)]
pub enum Tamper {
    #[default]
    None,
    Body,
    Signature,
    Deployment,
    Audience,
    Future,
}

pub struct ServerFixture {
    listener: TcpListener,
    signing: SigningKey,
    pub url: String,
}

impl ServerFixture {
    pub fn new(root: &Path) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("fake Zixcel listener");
        let address = listener.local_addr().expect("address");
        let url = format!("http://{address}/v1/topology");
        let signing = SigningKey::from_bytes(&[11; 32]);
        write_trust(root, &signing, &url);
        Self {
            listener,
            signing,
            url,
        }
    }

    pub fn start(self, tamper: Tamper) -> thread::JoinHandle<()> {
        thread::spawn(move || serve(&self.listener, &self.signing, &self.url, tamper))
    }
}

fn write_trust(root: &Path, signing: &SigningKey, _url: &str) {
    let public = signing.verifying_key().to_bytes();
    let value = json!({
        "schema": "zixcel://topology/response-authenticity-trust/v1",
        "algorithm": "Ed25519", "issuer": "zixcel-topology-api",
        "audience": "observer-fixture-client", "workload_id": "zixcel-topology-api",
        "security_domain": "wonderland-local",
        "deployment_id": "zixcel-topology-api-local", "trust_revision": 1,
        "proof_key_thumbprint": sha256_digest(&public),
        "public_key_base64url":
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(public)
    });
    let path = root.join("zixcel-response-trust.json");
    fs::write(&path, serde_json::to_vec(&value).expect("trust")).expect("write trust");
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("private trust");
}

fn serve(listener: &TcpListener, signing: &SigningKey, url: &str, tamper: Tamper) {
    let (mut stream, _) = listener.accept().expect("observation request");
    let mut request = [0_u8; 8_192];
    let count = stream.read(&mut request).expect("request bytes");
    let text = std::str::from_utf8(&request[..count]).expect("HTTP request");
    assert_eq!(
        header(text, "x-zixcel-audience"),
        Some("observer-fixture-client")
    );
    let nonce = header(text, "x-zixcel-request-nonce").expect("nonce");
    let now = i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_secs(),
    )
    .expect("time");
    let issued_at = if matches!(tamper, Tamper::Future) {
        now + 2
    } else {
        now
    };
    let body = br#"{"schema":"zixcel://topology/api-response/v1","summary":{"node_count":0,"edge_count":0,"disconnected_count":0},"document":{"schema":"zixcel://topology/document/v1","generated_at":"2026-07-30T00:00:00Z","nodes":[],"edges":[]}}"#;
    let proof = serde_json::to_vec(&json!({
        "schema": "zixcel://topology/signed-response-proof/v1",
        "algorithm": "Ed25519", "issuer": "zixcel-topology-api",
        "audience": if matches!(tamper, Tamper::Audience) { "different-client" } else { "observer-fixture-client" }, "workload_id": "zixcel-topology-api",
        "security_domain": "wonderland-local",
        "deployment_id": if matches!(tamper, Tamper::Deployment) {
            "attacker"
        } else { "zixcel-topology-api-local" },
        "trust_revision": 1, "request_method": "GET", "request_url": url,
        "request_nonce": nonce, "response_status": 200,
        "body_sha256": sha256_digest(body),
        "proof_key_thumbprint": sha256_digest(&signing.verifying_key().to_bytes()),
        "issued_at_epoch_s": issued_at, "expires_at_epoch_s": issued_at + 30
    }))
    .expect("proof");
    let mut signature = signing.sign(&signed_message(&proof, body)).to_bytes();
    if matches!(tamper, Tamper::Signature) {
        signature[0] ^= 1;
    }
    let delivered = if matches!(tamper, Tamper::Body) {
        [body.as_slice(), b" "].concat()
    } else {
        body.to_vec()
    };
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\
         X-Zixcel-Proof: {}\r\nX-Zixcel-Signature: {}\r\nConnection: close\r\n\r\n",
        delivered.len(),
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(proof),
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(signature)
    );
    stream.write_all(response.as_bytes()).expect("response");
    stream.write_all(&delivered).expect("body");
}

fn header<'a>(request: &'a str, target: &str) -> Option<&'a str> {
    request.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.eq_ignore_ascii_case(target).then_some(value.trim())
    })
}

fn signed_message(proof: &[u8], body: &[u8]) -> Vec<u8> {
    let mut value = Vec::with_capacity(DOMAIN.len() + 16 + proof.len() + body.len());
    value.extend_from_slice(DOMAIN);
    value.extend_from_slice(&(proof.len() as u64).to_be_bytes());
    value.extend_from_slice(&(body.len() as u64).to_be_bytes());
    value.extend_from_slice(proof);
    value.extend_from_slice(body);
    value
}
