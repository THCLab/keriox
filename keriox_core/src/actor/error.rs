use http::StatusCode;

#[cfg(feature = "storage-redb")]
use crate::database::redb::RedbError;
use crate::event_message::cesr_adapter::ParseError;
use crate::keys::KeysError;
#[cfg(feature = "oobi")]
use crate::oobi::{error::OobiError, Role};
#[cfg(feature = "oobi-manager")]
use crate::transport::TransportError;
use crate::{actor::SignedQueryError, error::Error as KeriError, prefix::IdentifierPrefix};
use said::version::error::Error as VersionError;

#[derive(Debug, thiserror::Error, serde::Serialize, serde::Deserialize)]
pub enum ActorError {
    #[cfg(feature = "oobi-manager")]
    #[error("network request failed")]
    TransportError(Box<TransportError>),

    #[error("keri error")]
    KeriError(#[from] KeriError),

    #[error("DB error: {0}")]
    DbError(String),

    #[cfg(feature = "oobi")]
    #[error("OOBI error")]
    OobiError(#[from] OobiError),

    #[error("processing query failed")]
    QueryError(#[from] SignedQueryError),

    #[error("Keri event parsing error: {0}")]
    ParseError(#[from] ParseError),

    #[error("location not found for {id:?}")]
    NoLocation { id: IdentifierPrefix }, // TODO: should be Oobi error

    #[error("wrong reply route")]
    WrongReplyRoute,

    #[cfg(feature = "oobi")]
    #[error("role {role:?} missing for {id:?}")]
    MissingRole { role: Role, id: IdentifierPrefix }, // TODO: should be Oobi error

    #[error("no identifier state for prefix {prefix:?}")]
    NoIdentState { prefix: IdentifierPrefix },

    #[error("Missing signer identifier")]
    MissingSignerId,

    #[error("Signing error: {0}")]
    SigningError(#[from] KeysError),

    #[error("Error: {0}")]
    GeneralError(String),

    #[error("KEL not found")]
    NotFound(IdentifierPrefix),

    #[error("Unexpected response: {0}")]
    UnexpectedResponse(String),
}

#[cfg(feature = "oobi-manager")]
impl From<TransportError> for ActorError {
    fn from(err: TransportError) -> Self {
        ActorError::TransportError(Box::new(err))
    }
}

impl From<VersionError> for ActorError {
    fn from(err: VersionError) -> Self {
        ActorError::KeriError(err.into())
    }
}

#[cfg(feature = "storage-redb")]
impl From<RedbError> for ActorError {
    fn from(err: RedbError) -> Self {
        ActorError::DbError(err.to_string())
    }
}

impl ActorError {
    pub fn http_status_code(&self) -> StatusCode {
        match self {
            ActorError::DbError(_) => StatusCode::INTERNAL_SERVER_ERROR,

            ActorError::KeriError(err) => match err {
                KeriError::DeserializeError(_) | KeriError::IncorrectDigest => {
                    StatusCode::BAD_REQUEST
                }

                KeriError::FaultySignatureVerification | KeriError::SignatureVerificationError => {
                    StatusCode::FORBIDDEN
                }

                _ => StatusCode::INTERNAL_SERVER_ERROR,
            },

            #[cfg(feature = "oobi")]
            ActorError::OobiError(OobiError::SignerMismatch) => StatusCode::UNAUTHORIZED,

            _ => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}
