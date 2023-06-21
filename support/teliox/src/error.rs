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

    #[error("Error")]
    MissingSealError,

    #[error("Missing issuer event")]
    MissingIssuerEventError,

    #[error("Event is out of order")]
    OutOfOrderError,

    #[error("Digests doesn't match")]
    DigestsNotMatchError,
}
