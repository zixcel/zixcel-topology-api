//! Replaces the complete SQLite file so deleted source metadata cannot survive in free pages.

use super::{open, replace, validate_path};
use crate::model::TopologyDocument;
use std::{
    fs,
    fs::OpenOptions,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

pub fn replace_file(path: &Path, document: &TopologyDocument) -> Result<(), String> {
    validate_path(path, false)?;
    let parent = path
        .parent()
        .ok_or("topology database requires a parent directory")?;
    let temporary = reserve(parent)?;
    let result = write_and_replace(&temporary, path, document);
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn write_and_replace(
    temporary: &Path,
    target: &Path,
    document: &TopologyDocument,
) -> Result<(), String> {
    {
        let mut database = open(temporary)?;
        replace(&mut database, document)?;
        let integrity: String = database
            .query_row("PRAGMA integrity_check", [], |row| row.get(0))
            .map_err(|error| error.to_string())?;
        if integrity != "ok" {
            return Err("topology replacement failed integrity check".into());
        }
        database.close().map_err(|(_, error)| error.to_string())?;
    }
    fs::File::open(temporary)
        .and_then(|file| file.sync_all())
        .map_err(|error| error.to_string())?;
    fs::rename(temporary, target).map_err(|error| error.to_string())?;
    if let Some(parent) = target.parent() {
        fs::File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| error.to_string())?;
    }
    Ok(())
}

fn reserve(parent: &Path) -> Result<PathBuf, String> {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "system time precedes Unix epoch".to_owned())?
        .as_nanos();
    for attempt in 0..32_u8 {
        let path = parent.join(format!(
            ".topology-{}-{nonce}-{attempt}.sqlite3",
            std::process::id()
        ));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        match options.open(&path) {
            Ok(file) => {
                file.sync_all().map_err(|error| error.to_string())?;
                return Ok(path);
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error.to_string()),
        }
    }
    Err("cannot reserve a private topology replacement file".into())
}
