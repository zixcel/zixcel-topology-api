use super::respond;
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
#[test]
fn invalid_nonce_method_url_and_disconnect_allow_next_request() {
    let root = tempfile::tempdir().unwrap();
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let private = root.path().join("key.json");
    crate::authentication::generate_identity(
        &private,
        &root.path().join("trust.json"),
        &crate::authentication::IdentityPolicy {
            audience: "test-client".into(),
            security_domain: "test-domain".into(),
            deployment_id: "test-deployment".into(),
        },
    )
    .unwrap();
    let signer = crate::authentication::ResponseSigner::load(&private).unwrap();
    let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
    let address = server.server_addr().to_ip().unwrap();
    let database = root.path().join("absent.db");
    let worker = std::thread::spawn(move || {
        for _ in 0..5 {
            let request = server.recv().unwrap();
            let _ = respond(request, &database, address, Some(&signer));
        }
    });
    for (method, path, nonce, expected) in [
        ("GET", "/v1/topology".into(), "!".repeat(43), 400),
        ("POST", "/v1/topology".into(), "A".repeat(43), 405),
        (
            "GET",
            format!("/v1/{}", "x".repeat(2_100)),
            "A".repeat(43),
            414,
        ),
    ] {
        let mut stream = std::net::TcpStream::connect(address).unwrap();
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(2)))
            .unwrap();
        write!(stream, "{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nX-Zixcel-Audience: test-client\r\nX-Zixcel-Request-Nonce: {nonce}\r\n\r\n").unwrap();
        let mut reply = String::new();
        stream.read_to_string(&mut reply).unwrap();
        assert!(
            reply.starts_with(&format!("HTTP/1.1 {expected}")),
            "{reply}"
        );
    }
    let mut disconnected = std::net::TcpStream::connect(address).unwrap();
    disconnected
        .write_all(b"GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .unwrap();
    drop(disconnected);
    let mut stream = std::net::TcpStream::connect(address).unwrap();
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(2)))
        .unwrap();
    stream
        .write_all(b"GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .unwrap();
    let mut reply = String::new();
    stream.read_to_string(&mut reply).unwrap();
    assert!(reply.starts_with("HTTP/1.1 503"));
    worker.join().unwrap();
}
