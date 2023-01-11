use http::StatusCode;

#[cfg(feature = "oobi")]
use crate::oobi::{error::OobiError, Role};
#[cfg(feature = "query")]
use crate::transport::TransportError;
use crate::{
    actor::SignedQueryError, database::DbError, error::Error as KeriError, prefix::IdentifierPrefix,
};

#[derive(Debug, thiserror::Error, serde::Serialize, serde::Deserialize)]
pub enum ActorError {
    #[cfg(feature = "query")]
    #[error("network request failed")]
    TransportError(Box<TransportError>),

    #[error("keri error")]
    KeriError(#[from] KeriError),

    #[error("DB error")]
    DbError(#[from] DbError),

    #[cfg(feature = "oobi")]
    #[error("OOBI error")]
    OobiError(#[from] OobiError),

    #[error("processing query failed")]
    QueryError(#[from] SignedQueryError),

    #[error("location not found for {id:?}")]
    NoLocation { id: IdentifierPrefix }, // TODO: should be Oobi error

    #[error("wrong reply route")]
    WrongReplyRoute,

    #[cfg(feature = "oobi")]
    #[error("role {role:?} missing for {id:?}")]
    MissingRole { role: Role, id: IdentifierPrefix }, // TODO: should be Oobi error

    #[error("no identifier state for prefix {prefix:?}")]
    NoIdentState { prefix: IdentifierPrefix },
}

#[cfg(feature = "query")]
impl From<TransportError> for ActorError {
    fn from(err: TransportError) -> Self {
        ActorError::TransportError(Box::new(err))
    }
}

impl ActorError {
    pub fn http_status_code(&self) -> StatusCode {
        match self {
            ActorError::DbError(_) => StatusCode::INTERNAL_SERVER_ERROR,

            ActorError::KeriError(err) => match err {
                KeriError::Base64DecodingError { .. }
                | KeriError::DeserializeError(_)
                | KeriError::IncorrectDigest => StatusCode::BAD_REQUEST,

                KeriError::Ed25519DalekSignatureError
                | KeriError::FaultySignatureVerification
                | KeriError::SignatureVerificationError => StatusCode::FORBIDDEN,

                _ => StatusCode::INTERNAL_SERVER_ERROR,
            },

            #[cfg(feature = "oobi")]
            ActorError::OobiError(OobiError::SignerMismatch) => StatusCode::UNAUTHORIZED,

            _ => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}
