use keri::error::Error as KeriError;
use sled_tables::error::Error as SledError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error(transparent)]
    DynError(#[from] Box<dyn std::error::Error>),

    #[error(transparent)]
    KeriError(#[from] KeriError),

    #[error(transparent)]
    SledError(#[from] sled::Error),

    #[error(transparent)]
    SledTablesError(#[from] SledError),

    #[error("{0}")]
    Generic(String),

    #[error(transparent)]
    VersionError(#[from] version::error::Error),

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
