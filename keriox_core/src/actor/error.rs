use http::StatusCode;

#[cfg(feature = "storage-redb")]
use crate::database::redb::RedbError;
use crate::event_message::cesr_adapter::ParseError;
use crate::keys::KeysError;
#[cfg(feature = "oobi")]
use crate::oobi::{error::OobiError, Role};
#[cfg(feature = "oobi-manager")]
use crate::transport::TransportError;
use crate::{
    actor::{QueryError, SignedQueryError},
    error::Error as KeriError,
    prefix::IdentifierPrefix,
};
use said::version::error::Error as VersionError;

#[derive(Debug, thiserror::Error, serde::Serialize, serde::Deserialize)]
pub enum ActorError {
    #[cfg(feature = "oobi-manager")]
    #[error("network request failed: {0}")]
    TransportError(Box<TransportError>),

    #[error("keri error: {0}")]
    KeriError(#[from] KeriError),

    #[error("DB error: {0}")]
    DbError(String),

    #[cfg(feature = "oobi")]
    #[error("OOBI error: {0}")]
    OobiError(#[from] OobiError),

    #[error("processing query failed: {0}")]
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

    #[error("KEL not found for {0}")]
    NotFound(IdentifierPrefix),

    #[error("Unexpected response: {0}")]
    UnexpectedResponse(String),

    #[error("query not supported here: {0}")]
    UnsupportedQuery(String),
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

            // The request body could not be read.
            ActorError::ParseError(_) => StatusCode::BAD_REQUEST,

            // The query was sent to a server that does not answer it.
            ActorError::UnsupportedQuery(_) => StatusCode::BAD_REQUEST,

            ActorError::MissingSignerId => StatusCode::BAD_REQUEST,

            // The server holds no log for the identifier asked about. That
            // is an answer, not a server failure.
            ActorError::NotFound(_) | ActorError::NoIdentState { .. } => StatusCode::NOT_FOUND,

            // The signer never named this server in an end role.
            #[cfg(feature = "oobi")]
            ActorError::MissingRole { .. } => StatusCode::FORBIDDEN,

            ActorError::KeriError(err) => keri_error_status(err),

            ActorError::QueryError(err) => match err {
                SignedQueryError::KeriError(err)
                | SignedQueryError::QueryError(QueryError::KeriError(err)) => {
                    keri_error_status(err)
                }
                SignedQueryError::QueryError(QueryError::UnknownId { .. }) => {
                    StatusCode::NOT_FOUND
                }
                SignedQueryError::UnknownSigner { .. } => StatusCode::UNAUTHORIZED,
                SignedQueryError::InvalidSignature => StatusCode::FORBIDDEN,
            },

            #[cfg(feature = "oobi")]
            ActorError::OobiError(OobiError::SignerMismatch) => StatusCode::UNAUTHORIZED,

            _ => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

fn keri_error_status(err: &KeriError) -> StatusCode {
    match err {
        KeriError::DeserializeError(_)
        | KeriError::IncorrectDigest
        | KeriError::MissingSignatures
        | KeriError::UnanchoredDelegatedEvent
        | KeriError::ConfigTraitViolation(_) => StatusCode::BAD_REQUEST,

        // The server does not know the log of the signer, so it cannot
        // verify who is asking.
        KeriError::UnknownSigner(_) => StatusCode::UNAUTHORIZED,

        KeriError::FaultySignatureVerification | KeriError::SignatureVerificationError => {
            StatusCode::FORBIDDEN
        }

        KeriError::AbandonedIdentifier(_) | KeriError::NonTransferableIdentifier(_) => {
            StatusCode::GONE
        }

        _ => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

#[cfg(test)]
mod tests {
    use http::StatusCode;

    use super::ActorError;
    use crate::{
        actor::{QueryError, SignedQueryError},
        error::Error,
        prefix::IdentifierPrefix,
    };

    #[test]
    fn an_event_after_the_end_of_a_log_is_gone() {
        for err in [
            Error::AbandonedIdentifier(IdentifierPrefix::default()),
            Error::NonTransferableIdentifier(IdentifierPrefix::default()),
        ] {
            assert_eq!(ActorError::KeriError(err).http_status_code(), StatusCode::GONE);
        }
    }

    #[test]
    fn a_query_the_server_does_not_serve_is_a_client_error() {
        assert_eq!(
            ActorError::UnsupportedQuery("mailbox".into()).http_status_code(),
            StatusCode::BAD_REQUEST
        );
    }

    #[test]
    fn an_identifier_the_server_holds_no_log_for_is_not_found() {
        for err in [
            ActorError::NotFound(IdentifierPrefix::default()),
            ActorError::NoIdentState {
                prefix: IdentifierPrefix::default(),
            },
            ActorError::QueryError(SignedQueryError::QueryError(QueryError::UnknownId {
                id: IdentifierPrefix::default(),
            })),
        ] {
            assert_eq!(err.http_status_code(), StatusCode::NOT_FOUND, "{err}");
        }
    }

    #[test]
    fn a_signer_the_server_does_not_know_is_unauthorized() {
        for err in [
            ActorError::KeriError(Error::UnknownSigner(IdentifierPrefix::default())),
            ActorError::QueryError(SignedQueryError::KeriError(Error::UnknownSigner(
                IdentifierPrefix::default(),
            ))),
            ActorError::QueryError(SignedQueryError::UnknownSigner {
                id: IdentifierPrefix::default(),
            }),
        ] {
            assert_eq!(err.http_status_code(), StatusCode::UNAUTHORIZED, "{err}");
        }
    }

    #[test]
    fn a_query_with_a_bad_signature_is_forbidden() {
        assert_eq!(
            ActorError::QueryError(SignedQueryError::InvalidSignature).http_status_code(),
            StatusCode::FORBIDDEN
        );
    }

    #[cfg(feature = "oobi")]
    #[test]
    fn a_signer_without_an_end_role_for_the_server_is_forbidden() {
        let err = ActorError::MissingRole {
            role: crate::oobi::Role::Watcher,
            id: IdentifierPrefix::default(),
        };
        assert_eq!(err.http_status_code(), StatusCode::FORBIDDEN);
    }

    #[test]
    fn a_server_failure_is_still_an_internal_error() {
        assert_eq!(
            ActorError::DbError("disk full".into()).http_status_code(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
    }
}
