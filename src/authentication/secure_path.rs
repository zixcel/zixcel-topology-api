use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;

use nix::unistd::Uid;

pub(super) fn secure_parent(path: &Path) -> Result<(), String> {
    if !path.is_absolute() {
        return Err("identity paths must be absolute".to_owned());
    }
    let parent = path
        .parent()
        .ok_or_else(|| "identity path has no parent".to_owned())?;
    let metadata = fs::symlink_metadata(parent).map_err(text)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != Uid::current().as_raw()
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err("identity parent must be owner-only and non-symlink".to_owned());
    }
    Ok(())
}

pub(super) fn secure_file(path: &Path, mode: u32) -> Result<(), String> {
    secure_parent(path)?;
    let metadata = fs::symlink_metadata(path).map_err(text)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.uid() != Uid::current().as_raw()
        || metadata.permissions().mode() & 0o777 != mode
    {
        return Err("identity file permissions or ownership are invalid".to_owned());
    }
    Ok(())
}

pub(super) fn write_new(path: &Path, value: &[u8], mode: u32) -> Result<(), String> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(path)
        .map_err(text)?;
    file.write_all(value).map_err(text)?;
    file.sync_all().map_err(text)
}

fn text(error: impl std::fmt::Display) -> String {
    error.to_string()
}
