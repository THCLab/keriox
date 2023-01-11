use keri::{oobi::Scheme, prefix::IdentifierPrefix};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ControllerError {
    #[error("Database error: {0}")]
    DatabaseError(#[from] keri::database::DbError),

    #[error("Transport error: {0}")]
    TransportError(#[from] keri::transport::TransportError),

    #[error("Communication error: {0}")]
    CommunicationError(String),

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

    #[error("Not group participant")]
    NotGroupParticipantError,

    #[error("Error while event processing: ")]
    EventProcessingError(#[from] keri::error::Error),

    #[error("No location for {id} with {scheme:?}")]
    NoLocationScheme {
        id: IdentifierPrefix,
        scheme: Scheme,
    },

    #[error("Query error: {0}")]
    QueryArgumentError(String),
}
