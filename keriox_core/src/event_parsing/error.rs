use base64::DecodeError;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Error, Debug, PartialEq, Serialize, Deserialize)]
pub enum Error {
    #[error("Base64 Decoding error")]
    Base64DecodingError,

    #[error("Unknown code")]
    UnknownCodeError,

    #[error("Empty code")]
    EmptyCodeError,

    #[error("Empty stream")]
    EmptyStreamError,

    #[error("Incorrect data length: {0}")]
    IncorrectLengthError(String),

    #[error("Payload serialization error")]
    PayloadSerializationError,
}

impl From<base64::DecodeError> for Error {
    fn from(_: DecodeError) -> Self {
        Error::Base64DecodingError
    }
}
