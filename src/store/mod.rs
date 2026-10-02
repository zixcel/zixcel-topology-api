mod file;
mod mutation;
mod query;

use std::{fs, path::Path};

use rusqlite::{Connection, OpenFlags};

pub use file::replace_file;
pub use mutation::{connect, disconnect, replace};
pub use query::read;

const MIGRATION: &str = include_str!("../../migrations/001_topology.sql");

pub fn open(path: &Path) -> Result<Connection, String> {
    validate_path(path, false)?;
    let connection = Connection::open(path).map_err(|error| error.to_string())?;
    connection
        .execute_batch("PRAGMA foreign_keys = ON; PRAGMA trusted_schema = OFF;")
        .and_then(|_| connection.execute_batch(MIGRATION))
        .map_err(|error| error.to_string())?;
    restrict_permissions(path)?;
    Ok(connection)
}

pub fn open_read_only(path: &Path) -> Result<Connection, String> {
    validate_path(path, true)?;
    let connection = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)
        .map_err(|error| error.to_string())?;
    connection
        .execute_batch("PRAGMA query_only = ON; PRAGMA trusted_schema = OFF;")
        .map_err(|error| error.to_string())?;
    Ok(connection)
}

pub(super) fn validate_path(path: &Path, require_file: bool) -> Result<(), String> {
    if !path.is_absolute() {
        return Err("topology database path must be absolute".into());
    }
    let parent = path
        .parent()
        .ok_or("topology database requires a parent directory")?;
    for ancestor in parent.ancestors() {
        let metadata = fs::symlink_metadata(ancestor).map_err(|error| error.to_string())?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err("topology database ancestor is not a physical directory".into());
        }
    }
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            Err("topology database is not a physical file".into())
        }
        Ok(_) => Ok(()),
        Err(error) if !require_file && error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.to_string()),
    }
}

#[cfg(unix)]
fn restrict_permissions(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).map_err(|error| error.to_string())
}

#[cfg(not(unix))]
fn restrict_permissions(_path: &Path) -> Result<(), String> {
    Ok(())
}

pub(super) fn json<T: serde::Serialize>(value: &T) -> Result<String, String> {
    serde_json::to_string(value).map_err(|error| error.to_string())
}

pub(super) fn text(error: rusqlite::Error) -> String {
    error.to_string()
}
