use ed25519_dalek;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Error, Debug, Serialize, Deserialize)]
pub enum Error {
    #[error("Incorrect data length: {0}")]
    IncorrectLengthError(String),

    #[error("Wrong seed type error")]
    WrongSeedTypeError,

    #[error("Deserialize error: {0}")]
    DeserializeError(String),

    #[error(transparent)]
    ParseError(#[from] cesrox::error::Error),

    #[error("ED25519Dalek signature error")]
    Ed25519DalekSignatureError,
}

impl From<ed25519_dalek::SignatureError> for Error {
    fn from(_: ed25519_dalek::SignatureError) -> Self {
        Error::Ed25519DalekSignatureError
    }
}
