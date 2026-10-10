mod support;

use std::os::unix::fs::PermissionsExt;

use crowsi_local_control_bridge::PrivateUnixListener;

#[test]
fn observer_socket_is_owner_only_and_removed_with_its_listener() {
    let root = support::private_root();
    let path = root.path().join("observer.sock");
    {
        let listener = PrivateUnixListener::bind(&path).expect("private socket");
        assert_eq!(
            std::fs::metadata(listener.path())
                .expect("socket metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
    assert!(!path.exists());
}
