use std::{
    fs::{Metadata, symlink_metadata},
    os::unix::{
        fs::{FileTypeExt, MetadataExt},
        net::UnixStream,
    },
    path::Path,
};

use nix::unistd::Uid;

use crate::ObserverError;

pub(crate) fn connect_private(path: &Path) -> Result<UnixStream, ObserverError> {
    if !path.is_absolute() {
        return Err(ObserverError::Transport);
    }
    let parent = path.parent().ok_or(ObserverError::Transport)?;
    if parent
        .canonicalize()
        .map_err(|_| ObserverError::Transport)?
        != parent
    {
        return Err(ObserverError::Transport);
    }
    let parent_meta = symlink_metadata(parent).map_err(|_| ObserverError::Transport)?;
    let before = symlink_metadata(path).map_err(|_| ObserverError::Transport)?;
    let uid = Uid::effective().as_raw();
    if !parent_meta.is_dir()
        || parent_meta.uid() != uid
        || parent_meta.mode() & 0o077 != 0
        || !before.file_type().is_socket()
        || before.uid() != uid
        || before.mode() & 0o777 != 0o600
    {
        return Err(ObserverError::Transport);
    }
    let stream = UnixStream::connect(path).map_err(|_| ObserverError::Transport)?;
    let after = symlink_metadata(path).map_err(|_| ObserverError::Transport)?;
    if !same(&before, &after) {
        return Err(ObserverError::Transport);
    }
    Ok(stream)
}

fn same(left: &Metadata, right: &Metadata) -> bool {
    left.dev() == right.dev()
        && left.ino() == right.ino()
        && left.uid() == right.uid()
        && left.gid() == right.gid()
        && left.mode() == right.mode()
        && left.ctime() == right.ctime()
        && left.ctime_nsec() == right.ctime_nsec()
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        os::unix::{
            fs::{PermissionsExt, symlink},
            net::UnixListener,
        },
    };

    use super::connect_private;

    #[test]
    fn socket_path_rejects_relative_symlink_and_broad_modes() {
        let root = tempfile::tempdir().expect("temporary directory");
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700))
            .expect("private parent");
        let socket = root.path().join("observer.sock");
        let _listener = UnixListener::bind(&socket).expect("listener");
        fs::set_permissions(&socket, fs::Permissions::from_mode(0o600)).expect("private socket");
        assert!(connect_private(&socket).is_ok());
        assert!(connect_private(std::path::Path::new("observer.sock")).is_err());

        let link = root.path().join("observer-link.sock");
        symlink(&socket, &link).expect("socket symlink");
        assert!(connect_private(&link).is_err());

        fs::set_permissions(&socket, fs::Permissions::from_mode(0o666)).expect("broad socket");
        assert!(connect_private(&socket).is_err());
    }
}
