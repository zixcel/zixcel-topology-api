use std::{
    fs::{File, read_to_string},
    io::Read,
    os::unix::net::UnixStream,
};

use nix::{
    sys::socket::{getsockopt, sockopt::PeerCredentials},
    unistd::{Gid, Uid},
};
use sha2::{Digest, Sha256};

use crate::ObserverError;

pub(crate) fn attest_server(stream: &UnixStream) -> Result<(), ObserverError> {
    let peer = getsockopt(stream, PeerCredentials).map_err(|_| ObserverError::Transport)?;
    let pid = u32::try_from(peer.pid()).map_err(|_| ObserverError::Transport)?;
    let before = start_ticks(pid)?;
    let peer_digest = process_digest(pid)?;
    let after = start_ticks(pid)?;
    let self_digest = process_digest(std::process::id())?;
    if pid == 0
        || before == 0
        || before != after
        || peer.uid() != Uid::effective().as_raw()
        || peer.gid() != Gid::effective().as_raw()
        || peer_digest != self_digest
    {
        return Err(ObserverError::Transport);
    }
    Ok(())
}

fn process_digest(pid: u32) -> Result<[u8; 32], ObserverError> {
    let mut file = File::open(format!("/proc/{pid}/exe")).map_err(|_| ObserverError::Transport)?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 8_192];
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|_| ObserverError::Transport)?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    Ok(digest.finalize().into())
}

fn start_ticks(pid: u32) -> Result<u64, ObserverError> {
    let stat = read_to_string(format!("/proc/{pid}/stat")).map_err(|_| ObserverError::Transport)?;
    let close = stat.rfind(')').ok_or(ObserverError::Transport)?;
    stat.get(close + 2..)
        .and_then(|tail| tail.split_whitespace().nth(19))
        .and_then(|value| value.parse().ok())
        .ok_or(ObserverError::Transport)
}
