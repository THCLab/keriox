use ed25519_dalek;
use serde::{Serialize, Deserialize};
use thiserror::Error;

#[derive(Error, Debug, Serialize, Deserialize)]
pub enum Error {
    #[error(transparent)]
    DeriviationCodeError(#[from] crate::sai::error::Error),

    #[error("Incorrect data length: {0}")]
    IncorrectLengthError(String),

    #[error("Wrong signature type error")]
    WrongSignatureTypeError,

    #[error("Wrong key type error")]
    WrongKeyTypeError,

    #[error("Wrong seed type error")]
    WrongSeedTypeError,

    #[error("Deserialize error: {0}")]
    DeserializeError(String),

    #[error(transparent)]
    ParseError(#[from] crate::event_parsing::error::Error),

    #[error("ED25519Dalek signature error")]
    Ed25519DalekSignatureError,
}

impl From<ed25519_dalek::SignatureError> for Error {
    fn from(_: ed25519_dalek::SignatureError) -> Self {
        Error::Ed25519DalekSignatureError
    }
}