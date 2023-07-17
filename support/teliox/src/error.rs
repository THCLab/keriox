use keri::error::Error as KeriError;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Error, Debug, Serialize, Deserialize)]
pub enum Error {
    #[error(transparent)]
    KeriError(#[from] KeriError),

    #[error("Sled database error")]
    SledError,

    #[error("{0}")]
    Generic(String),

    #[error("Tel event encoding error")]
    EncodingError(String),

    #[error("Escrow database error")]
    EscrowDatabaseError,

    #[error("Error")]
    MissingSealError,

    #[error("Missing issuer event")]
    MissingIssuerEventError,

    #[error("Missing issuer event")]
    MissingRegistryError,

    #[error("Event is out of order")]
    OutOfOrderError,

    #[error("Digests doesn't match")]
    DigestsNotMatchError,

    #[error("Unknown identifier")]
    UnknownIdentifierError,

    #[error("Event is already accepted in TEL")]
    EventAlreadySavedError,

    #[error("Locking error")]
    RwLockingError,
}

impl From<sled::Error> for Error {
    fn from(_: sled::Error) -> Self {
        Error::SledError
    }
}

impl From<sled_tables::error::Error> for Error {
    fn from(_: sled_tables::error::Error) -> Self {
        Error::SledError
    }
}
