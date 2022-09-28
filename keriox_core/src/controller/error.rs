use thiserror::Error;

use crate::{oobi::Scheme, prefix::IdentifierPrefix};

#[derive(Error, Debug)]
pub enum ControllerError {
    #[error("Database error: {0}")]
    DatabaseError(#[from] crate::database::DbError),

    #[error("Communication error: {0}")]
    CommunicationError(String),

    #[error("Transport error: {0}")]
    TransportError(#[from] crate::transport::TransportError),

    #[error("Inception event error: {0}")]
    InceptionError(String),

    #[error("Can't generate event: {0}")]
    EventGenerationError(String),

    #[error("Can't parse event")]
    EventParseError,

    #[error("Wrong event format")]
    EventFormatError,

    #[error("Can't parse attachment")]
    AttachmentParseError,

    #[error("Improper witness prefix, should be basic prefix")]
    WrongWitnessPrefixError,

    #[error("missing event")]
    MissingEventError,

    #[error("Wrong event type")]
    WrongEventTypeError,

    #[error("Unknown identifier")]
    UnknownIdentifierError,

    #[error("Error while event processing: ")]
    EventProcessingError(#[from] crate::error::Error),

    #[error("No location for id {id:?} with scheme {scheme:?}")]
    NoLocation {
        id: IdentifierPrefix,
        scheme: Scheme,
    },
}
