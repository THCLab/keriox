use keri_core::{
    actor::prelude::VersionError,
    event_message::cesr_adapter::ParseError, oobi::Scheme, oobi::error::OobiError,
    prefix::IdentifierPrefix, processor::validator::VerificationError,
};
use thiserror::Error;

use crate::{
    communication::SendingError,
    identifier::{mechanics::MechanicsError, query::WatcherResponseError},
};

#[derive(Error, Debug)]
pub enum ControllerError {
    #[error("Database error: {0}")]
    DatabaseError(String),

    #[error("Cache error: {0}")]
    CacheError(String),

    #[error(transparent)]
    SendingError(#[from] SendingError),

    #[error("Keri event parsing error: {0}")]
    ParseError(#[from] ParseError),

    #[error("Unknown identifier")]
    UnknownIdentifierError,

    #[error("transparent")]
    EventProcessingError(#[from] keri_core::error::Error),

    #[error("Keri version error: ")]
    VersionError(#[from] VersionError),

    #[error("No location for {id} with {scheme:?}")]
    NoLocationScheme {
        id: IdentifierPrefix,
        scheme: Scheme,
    },

    #[error("Query error: {0}")]
    QueryArgumentError(String),

    #[error("Cesr error")]
    CesrFormatError,

    #[error("Wrong signature")]
    FaultySignature,

    #[error("Verification failed for following elements: {0:?}")]
    VerificationError(Vec<(VerificationError, String)>),

    #[error(transparent)]
    TelError(#[from] teliox::error::Error),

    #[error("Error: {0}")]
    OtherError(String),

    #[error("Oobi error: {0}")]
    OobiError(String),

    #[error(transparent)]
    Mechanic(#[from] MechanicsError),

    #[error("Watcher response error: {0}")]
    WatcherResponseError(#[from] WatcherResponseError),
}

impl From<OobiError> for ControllerError {
    fn from(e: OobiError) -> Self {
        ControllerError::OobiError(e.to_string())
    }
}

impl From<redb::DatabaseError> for ControllerError {
    fn from(e: redb::DatabaseError) -> Self {
        ControllerError::CacheError(e.to_string())
    }
}

impl From<redb::TransactionError> for ControllerError {
    fn from(e: redb::TransactionError) -> Self {
        ControllerError::CacheError(e.to_string())
    }
}

impl From<redb::TableError> for ControllerError {
    fn from(e: redb::TableError) -> Self {
        ControllerError::CacheError(e.to_string())
    }
}

impl From<redb::StorageError> for ControllerError {
    fn from(e: redb::StorageError) -> Self {
        ControllerError::CacheError(e.to_string())
    }
}

impl From<redb::CommitError> for ControllerError {
    fn from(e: redb::CommitError) -> Self {
        ControllerError::CacheError(e.to_string())
    }
}
