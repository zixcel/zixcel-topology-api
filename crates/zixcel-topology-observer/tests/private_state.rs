mod support;

use std::{
    fs,
    os::unix::fs::{PermissionsExt, symlink},
};

use zixcel_topology_observer::{ObserverError, ResponseReplayStore, read_owner_only_json};

#[test]
fn response_replay_state_is_owner_only_and_symlink_safe() {
    let root = support::private_root();
    let state = root.path().join("observer.sqlite3");
    ResponseReplayStore::open(&state).expect("private replay state");
    assert_eq!(
        fs::metadata(&state)
            .expect("state metadata")
            .permissions()
            .mode()
            & 0o777,
        0o600
    );

    let broad = root.path().join("broad.sqlite3");
    fs::write(&broad, []).expect("broad state");
    fs::set_permissions(&broad, fs::Permissions::from_mode(0o644)).expect("broad mode");
    assert!(matches!(
        ResponseReplayStore::open(&broad),
        Err(ObserverError::Storage)
    ));

    let link = root.path().join("linked.sqlite3");
    symlink(&state, &link).expect("state symlink");
    assert!(matches!(
        ResponseReplayStore::open(&link),
        Err(ObserverError::Storage)
    ));
}

#[test]
fn bounded_json_reader_rejects_symlinks_and_broad_parent_access() {
    let root = support::private_root();
    let source = root.path().join("bundle.json");
    fs::write(&source, b"{\"schema\":\"test\"}").expect("bundle");
    fs::set_permissions(&source, fs::Permissions::from_mode(0o600)).expect("private bundle");
    let value: serde_json::Value = read_owner_only_json(&source, 1_024).expect("secure JSON");
    assert_eq!(value["schema"], "test");

    let link = root.path().join("bundle-link.json");
    symlink(&source, &link).expect("bundle symlink");
    assert!(matches!(
        read_owner_only_json::<serde_json::Value>(&link, 1_024),
        Err(ObserverError::Storage)
    ));

    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o755)).expect("broad parent");
    assert!(matches!(
        read_owner_only_json::<serde_json::Value>(&source, 1_024),
        Err(ObserverError::Storage)
    ));
}
