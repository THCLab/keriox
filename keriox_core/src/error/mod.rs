use said::version::error::Error as VersionError;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[cfg(feature = "storage-redb")]
use crate::database::redb::RedbError;
use crate::{
    event::sections::key_config::SignatureError, event_message::cesr_adapter::ParseError,
    prefix::IdentifierPrefix, processor::validator::VerificationError,
};

pub mod serializer_error;

#[derive(Error, Debug, Serialize, Deserialize)]
pub enum Error {
    #[error("Error during Serialization: {0}")]
    SerializationError(String),

    #[error("Error while applying event: {0}")]
    SemanticError(String),

    #[error("Event signature verification faulty")]
    FaultySignatureVerification,

    #[error("Error while applying event: out of order event")]
    EventOutOfOrderError,

    #[error("Error while applying event: missing delegator source seal: {0}")]
    MissingDelegatorSealError(IdentifierPrefix),

    #[error("Error while applying event: missing delegating event")]
    MissingDelegatingEventError,

    #[error("Error while applying event: duplicate event")]
    EventDuplicateError,

    #[error("Not enough signatures while verifying")]
    NotEnoughSigsError,

    #[error("Not enough receipts")]
    NotEnoughReceiptsError,

    #[error("Event not yet in database")]
    MissingEvent,

    #[error("Event has no signatures")]
    MissingSignatures,

    #[error("No signer")]
    MissingSigner,

    #[error("No signer identifier in db {0}")]
    UnknownSigner(IdentifierPrefix),

    #[error("Signature verification failed")]
    SignatureVerificationError,

    #[error("Receipt signature verification failed")]
    ReceiptVerificationError,

    #[error("Deserialize error: {0}")]
    DeserializeError(#[from] ParseError),

    #[error("Identifier is not indexed into the DB")]
    NotIndexedError,

    #[error("Identifier ID is already present in the DB")]
    IdentifierPresentError,

    #[error("Failed to obtain mutable ref to Ark of KeyManager")]
    MutArcKeyVaultError,

    #[error("Sled error")]
    SledError,

    #[error("Keri serializer error: {0}")]
    SerdeSerError(#[from] serializer_error::Error),

    #[error("mutex is poisoned")]
    MutexPoisoned,

    #[error("RwLock poisoned")]
    RwLockingError,

    #[error("Incorrect event digest")]
    IncorrectDigest,

    #[error("No digest of event set")]
    EventDigestError,

    #[cfg(feature = "query")]
    #[error(transparent)]
    QueryError(#[from] crate::query::QueryError),

    #[error("Database err")]
    DbError,

    #[error("Event generation error: {0}")]
    EventGenerationError(String),

    #[error(transparent)]
    PrefixModuleError(#[from] crate::prefix::error::Error),

    #[error("CESR error")]
    CesrError,

    #[error("Version error")]
    VersionError,

    #[error("SAI error")]
    SAIError,

    #[error("Signing error")]
    SigningError,

    #[error(transparent)]
    KeyConfigError(SignatureError),

    #[error(transparent)]
    VerificationError(#[from] VerificationError),
}

impl From<VersionError> for Error {
    fn from(_: VersionError) -> Self {
        Error::VersionError
    }
}

impl From<said::error::Error> for Error {
    fn from(_: said::error::Error) -> Self {
        Error::SAIError
    }
}

#[cfg(feature = "storage-redb")]
impl From<RedbError> for Error {
    fn from(_: RedbError) -> Self {
        Error::DbError
    }
}

impl From<crate::keys::KeysError> for Error {
    fn from(_: crate::keys::KeysError) -> Self {
        Error::SigningError
    }
}

impl From<SignatureError> for Error {
    fn from(value: SignatureError) -> Self {
        match value {
            SignatureError::NotEnoughSigsError => Error::NotEnoughSigsError,
            e => Error::KeyConfigError(e),
        }
    }
}
