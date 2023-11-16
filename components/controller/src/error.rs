use keri::{
    actor::prelude::VersionError, event_message::cesr_adapter::ParseError, oobi::Scheme,
    prefix::IdentifierPrefix,
};
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

    #[error("Keri event parsing error: {0}")]
    ParseError(#[from] ParseError),

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

    #[error("transparent")]
    EventProcessingError(#[from] keri::error::Error),

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
    VerificationError(Vec<(ControllerError, String)>),

    #[error(transparent)]
    TelError(#[from] teliox::error::Error),

    #[error("Error: {0}")]
    OtherError(String),
}
