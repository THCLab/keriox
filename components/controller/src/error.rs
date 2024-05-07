use keri_core::{
    actor::prelude::VersionError, event_message::cesr_adapter::ParseError, oobi::Scheme,
    prefix::IdentifierPrefix, processor::validator::VerificationError,
};
use thiserror::Error;

use crate::{communication::SendingError, identifier::{mechanics::MechanicsError, query::WatcherResponseError}};

#[derive(Error, Debug)]
pub enum ControllerError {
    #[error("Database error: {0}")]
    DatabaseError(#[from] keri_core::database::DbError),

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

    #[error(transparent)]
    Mechanic(#[from] MechanicsError),

    #[error("Watcher response error: {0}")]
    WatcherResponseError(#[from] WatcherResponseError)

}
