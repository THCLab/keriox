use thiserror::Error;

#[derive(Error, Debug)]
pub enum ControllerError {
    #[error("Database error: {0}")]
    DatabaseError(String),
    #[error("Communication error: {0}")]
    CommunicationError(String),
    #[error("Inception event error")]
    InceptionError,
    #[error("can't generate rotation event")]
    RotationError,
    #[error("can't parse event: {0}")]
    ParseEventError(String),
    #[error("can't notify: {0}")]
    NotificationError(String),
    #[error("missing event")]
    MissingEventError,
    #[error("general error {0}")]
    GeneralError(String),
    #[error("unknown identifier")]
    UnknownIdentifierError,
    #[error("Error while event processing: ")]
    EventProcessingError(#[from] crate::error::Error),
}