use base64::DecodeError;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Error, Debug, Serialize, Deserialize)]
pub enum Error {
    #[error("Base64 Decoding error")]
    Base64DecodingError,

    #[error("Unknown code")]
    UnknownCodeError,

    #[error("Empty code")]
    EmptyCodeError,

    #[error("Incorrect data length: {0}")]
    IncorrectLengthError(String),
}

impl From<base64::DecodeError> for Error {
    fn from(_: DecodeError) -> Self {
        Error::Base64DecodingError
    }
}