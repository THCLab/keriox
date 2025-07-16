use keri_core::error::Error as KeriError;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Error, Debug, Serialize, Deserialize)]
pub enum Error {
    #[error(transparent)]
    KeriError(#[from] KeriError),

    #[error("Redb database error")]
    RedbError,

    #[error("{0}")]
    Generic(String),

    #[error("Tel event encoding error")]
    EncodingError(String),

    #[error("Escrow database error: {0}")]
    EscrowDatabaseError(String),

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

impl From<redb::TransactionError> for Error {
    fn from(_: redb::TransactionError) -> Self {
        Error::RedbError
    }
}

impl From<redb::TableError> for Error {
    fn from(_: redb::TableError) -> Self {
        Error::RedbError
    }
}

impl From<redb::CommitError> for Error {
    fn from(_: redb::CommitError) -> Self {
        Error::RedbError
    }
}

impl From<redb::StorageError> for Error {
    fn from(_: redb::StorageError) -> Self {
        Error::RedbError
    }
}
