use thiserror::Error;

#[derive(Error, Debug)]
pub enum ControllerError {
    #[error("Database error: {0}")]
    DatabaseError(String),

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

    #[error("Error while event processing: ")]
    EventProcessingError(#[from] crate::error::Error),
}
