use std::{
    fs::{Metadata, OpenOptions, symlink_metadata},
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
};

use nix::unistd::{Gid, Uid};

use crate::ObserverError;

#[derive(Clone, Copy)]
pub(crate) enum FilePolicy {
    OwnerOnly,
    ProvisionedPolicy,
}

pub(crate) fn read(
    path: &Path,
    maximum: usize,
    policy: FilePolicy,
) -> Result<Vec<u8>, ObserverError> {
    let before = validated_metadata(path, policy)?;
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| ObserverError::Storage)?;
    let opened = file.metadata().map_err(|_| ObserverError::Storage)?;
    if !same(&before, &opened) {
        return Err(ObserverError::Storage);
    }
    let mut bytes = Vec::new();
    (&mut file)
        .take(u64::try_from(maximum).unwrap_or(u64::MAX).saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_| ObserverError::Storage)?;
    let handle_after = file.metadata().map_err(|_| ObserverError::Storage)?;
    let path_after = symlink_metadata(path).map_err(|_| ObserverError::Storage)?;
    if bytes.is_empty()
        || bytes.len() > maximum
        || !same(&opened, &handle_after)
        || !same(&opened, &path_after)
    {
        return Err(ObserverError::Storage);
    }
    Ok(bytes)
}

fn validated_metadata(path: &Path, policy: FilePolicy) -> Result<Metadata, ObserverError> {
    if !path.is_absolute() {
        return Err(ObserverError::Storage);
    }
    let parent = path.parent().ok_or(ObserverError::Storage)?;
    if parent.canonicalize().map_err(|_| ObserverError::Storage)? != parent {
        return Err(ObserverError::Storage);
    }
    let parent_meta = symlink_metadata(parent).map_err(|_| ObserverError::Storage)?;
    let metadata = symlink_metadata(path).map_err(|_| ObserverError::Storage)?;
    let owner = Uid::effective().as_raw();
    let group = Gid::effective().as_raw();
    let local_parent = parent_meta.is_dir()
        && parent_meta.uid() == owner
        && parent_meta.mode().trailing_zeros() >= 6;
    let local_file =
        metadata.is_file() && metadata.uid() == owner && metadata.mode() & 0o777 == 0o600;
    let provisioned_parent = parent_meta.is_dir()
        && parent_meta.uid() == 0
        && parent_meta.gid() == group
        && parent_meta.mode() & 0o777 == 0o750;
    let provisioned_file = metadata.is_file()
        && metadata.uid() == 0
        && metadata.gid() == group
        && metadata.mode() & 0o777 == 0o640;
    let valid = match policy {
        FilePolicy::OwnerOnly => local_parent && local_file,
        FilePolicy::ProvisionedPolicy => {
            (local_parent && local_file) || (provisioned_parent && provisioned_file)
        }
    };
    valid.then_some(metadata).ok_or(ObserverError::Storage)
}

fn same(left: &Metadata, right: &Metadata) -> bool {
    left.dev() == right.dev()
        && left.ino() == right.ino()
        && left.uid() == right.uid()
        && left.gid() == right.gid()
        && left.mode() == right.mode()
        && left.size() == right.size()
        && left.ctime() == right.ctime()
        && left.ctime_nsec() == right.ctime_nsec()
        && left.mtime() == right.mtime()
        && left.mtime_nsec() == right.mtime_nsec()
}
