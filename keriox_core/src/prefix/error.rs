use base64::DecodeError;
use ed25519_dalek;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error(transparent)]
    DeriviationCodeError(#[from] crate::derivation::error::Error),

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

    #[error(transparent)]
    Ed25519DalekSignatureError(#[from] ed25519_dalek::SignatureError),
}
