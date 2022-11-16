use core::num::ParseIntError;

use base64::DecodeError;
use ed25519_dalek;
use serde::{Serialize, Deserialize};
use thiserror::Error;

use crate::prefix::IdentifierPrefix;

pub mod serializer_error;

#[derive(Error, Debug, Serialize, Deserialize)]
pub enum Error {
    #[error("Error during Serialization: {0}")]
    SerializationError(String),

    // TODO: add line/col
    #[error("JSON Serialization error")]
    JsonDeserError,

    #[error("CBOR Serialization error")]
    CborDeserError,

    #[error("MessagePack Serialization error")]
    MsgPackDeserError ,

    #[error("Error parsing numerical value")]
    ParseIntError ,

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

    #[error("Signature duplicate while verifing")]
    DuplicateSignature,

    #[error("Too many signatures while verifing")]
    TooManySignatures,

    #[error("Not enough receipts")]
    NotEnoughReceiptsError,

    #[error("Event not yet in database")]
    MissingEvent,

    #[error("Event has no signatures")]
    MissingSignatures,

    #[error("No signer")]
    MissingSigner,

    #[error("Signature verification failed")]
    SignatureVerificationError,

    #[error("Receipt signature verification failed")]
    ReceiptVerificationError,

    #[error("Deserialize error: {0}")]
    DeserializeError(String),

    #[error("Identifier is not indexed into the DB")]
    NotIndexedError,

    #[error("Identifier ID is already present in the DB")]
    IdentifierPresentError,

    #[error("Base64 Decoding error")]
    Base64DecodingError,

    #[error("Improper Prefix Type")]
    ImproperPrefixType,

    #[error("Storage error")]
    StorageError,

    #[error("Invalid identifier state")]
    InvalidIdentifierStat,

    #[cfg(feature = "async")]
    #[error("Zero send error")]
    ZeroSendError,

    #[error("Failed to obtain mutable ref to Ark of KeyManager")]
    MutArcKeyVaultError,

    #[error("ED25519Dalek signature error")]
    Ed25519DalekSignatureError,

    #[error("Sled error")]
    SledError,

    #[error("Keri serializer error: {0}")]
    SerdeSerError(#[from] serializer_error::Error),

    #[error("mutex is poisoned")]
    MutexPoisoned,

    #[error("Incorrect event digest")]
    IncorrectDigest,

    #[cfg(feature = "query")]
    #[error(transparent)]
    QueryError(#[from] crate::query::QueryError),

    #[error(transparent)]
    DbError(#[from] crate::database::DbError),

    #[error("Event generation error: {0}")]
    EventGenerationError(String),

    #[error(transparent)]
    PrefixModuleError(#[from] crate::prefix::error::Error),

    #[error("Cesr error")]
    CesrError,
}

impl From<ParseIntError> for Error {
    fn from(_: ParseIntError) -> Self {
        Error::ParseIntError
    }
}

impl From<base64::DecodeError> for Error {
    fn from(_: DecodeError) -> Self {
        Error::Base64DecodingError
    }
}

impl From<ed25519_dalek::SignatureError> for Error {
    fn from(_: ed25519_dalek::SignatureError) -> Self {
        Error::Ed25519DalekSignatureError
    }
}

impl From<sled::Error> for Error {
    fn from(_: sled::Error) -> Self {
        Error::SledError
    }
}
