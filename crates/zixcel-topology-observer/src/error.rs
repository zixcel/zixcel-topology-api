use thiserror::Error;

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum ObserverError {
    #[error("closed observation contract rejected")]
    Contract,
    #[error("Crowsi authorization binding rejected")]
    Authorization,
    #[error("owner-only local transport unavailable")]
    Transport,
    #[error("Zixcel response authenticity rejected")]
    ResponseAuthenticity,
    #[error("trusted time evidence rejected")]
    Time,
    #[error("response nonce replay rejected")]
    Replay,
    #[error("durable observer state unavailable")]
    Storage,
}

impl From<rusqlite::Error> for ObserverError {
    fn from(_: rusqlite::Error) -> Self {
        Self::Storage
    }
}
