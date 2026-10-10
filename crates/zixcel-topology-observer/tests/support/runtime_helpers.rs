fn identity_status_trust() -> IdentityStatusTrust {
    let signer = ed25519_dalek::SigningKey::from_bytes(&[9; 32]);
    IdentityStatusTrust::new(
        signer.verifying_key().to_bytes(),
        "ihat-status-key:topology-fixture:1",
        "ihat://identity-authority",
        "crowsi://topology-observer/current-status",
        "service:crowsi",
    )
    .expect("status trust")
}

pub fn private_root() -> TempDir {
    let root = tempfile::tempdir().expect("temporary directory");
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).expect("private directory");
    root
}

fn executable_digest() -> String {
    sha256_digest(&fs::read("/proc/self/exe").expect("current executable"))
}

fn write_frame(stream: &mut UnixStream, value: &[u8]) {
    let length = u32::try_from(value.len()).expect("frame length");
    stream.write_all(&length.to_be_bytes()).expect("length");
    stream.write_all(value).expect("frame");
}
