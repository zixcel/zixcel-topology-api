use std::{
    fs::{OpenOptions, symlink_metadata},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
};

use nix::unistd::Uid;
use rusqlite::{Connection, OpenFlags, params};

use crate::ObserverError;

pub struct ResponseReplayStore {
    connection: Connection,
}

impl ResponseReplayStore {
    /// Opens durable response-nonce and monotonic-time state.
    ///
    /// # Errors
    ///
    /// Rejects non-private state paths or an incompatible schema.
    pub fn open(path: &Path) -> Result<Self, ObserverError> {
        let connection = open_private(path)?;
        connection.execute_batch(
            "PRAGMA trusted_schema=OFF; PRAGMA synchronous=FULL;
             CREATE TABLE IF NOT EXISTS observer_meta(
               id INTEGER PRIMARY KEY CHECK(id=1), schema TEXT NOT NULL, watermark INTEGER NOT NULL
             ) STRICT;
             INSERT OR IGNORE INTO observer_meta VALUES(
               1,'crowsi://topology-observer/replay-state/v1',0
             );
             CREATE TABLE IF NOT EXISTS consumed_response(
               nonce TEXT PRIMARY KEY, body_sha256 TEXT NOT NULL, consumed_at INTEGER NOT NULL
             ) STRICT;",
        )?;
        let schema: String =
            connection.query_row("SELECT schema FROM observer_meta WHERE id=1", [], |row| {
                row.get(0)
            })?;
        if schema != "crowsi://topology-observer/replay-state/v1" {
            return Err(ObserverError::Storage);
        }
        Ok(Self { connection })
    }

    pub(crate) fn consume(
        &mut self,
        nonce: &str,
        body_sha256: &str,
        now: i64,
    ) -> Result<(), ObserverError> {
        let transaction = self.connection.transaction()?;
        let watermark: i64 = transaction.query_row(
            "SELECT watermark FROM observer_meta WHERE id=1",
            [],
            |row| row.get(0),
        )?;
        if now < watermark {
            return Err(ObserverError::Time);
        }
        let inserted = transaction.execute(
            "INSERT OR IGNORE INTO consumed_response VALUES(?1,?2,?3)",
            params![nonce, body_sha256, now],
        )?;
        if inserted != 1 {
            return Err(ObserverError::Replay);
        }
        transaction.execute("UPDATE observer_meta SET watermark=?1 WHERE id=1", [now])?;
        transaction.commit()?;
        Ok(())
    }
}

fn open_private(path: &Path) -> Result<Connection, ObserverError> {
    if !path.is_absolute() {
        return Err(ObserverError::Storage);
    }
    let parent = path.parent().ok_or(ObserverError::Storage)?;
    let parent_meta = symlink_metadata(parent).map_err(|_| ObserverError::Storage)?;
    if parent.canonicalize().map_err(|_| ObserverError::Storage)? != parent
        || !parent_meta.is_dir()
        || parent_meta.uid() != Uid::effective().as_raw()
        || parent_meta.mode() & 0o077 != 0
    {
        return Err(ObserverError::Storage);
    }
    if !path.exists() {
        OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(path)
            .map_err(|_| ObserverError::Storage)?;
    }
    let before = symlink_metadata(path).map_err(|_| ObserverError::Storage)?;
    if !before.is_file()
        || before.uid() != Uid::effective().as_raw()
        || before.mode() & 0o777 != 0o600
    {
        return Err(ObserverError::Storage);
    }
    let connection = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW
            | OpenFlags::SQLITE_OPEN_EXRESCODE,
    )
    .map_err(|_| ObserverError::Storage)?;
    let after = symlink_metadata(path).map_err(|_| ObserverError::Storage)?;
    if before.dev() != after.dev() || before.ino() != after.ino() {
        return Err(ObserverError::Storage);
    }
    connection
        .pragma_update(None, "journal_mode", "DELETE")
        .and_then(|()| connection.execute_batch("PRAGMA foreign_keys=ON; PRAGMA secure_delete=ON;"))
        .map_err(|_| ObserverError::Storage)?;
    Ok(connection)
}
