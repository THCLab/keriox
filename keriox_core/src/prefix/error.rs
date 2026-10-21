use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::keys::KeysError;

#[derive(Error, Debug, Serialize, Deserialize)]
pub enum Error {
    #[error("Incorrect data length: {0}")]
    IncorrectLengthError(String),

    #[error("Wrong seed type error")]
    WrongSeedTypeError,

    #[error("Deserialize error: {0}")]
    DeserializeError(String),

    #[error("Signature index {0} does not fit in 16 bits")]
    IndexOutOfRange(u32),

    #[error("Sequence number {0} does not fit in 64 bits")]
    SnOutOfRange(u128),

    #[error(transparent)]
    ParseError(#[from] cesrox::error::Error),

    #[error(transparent)]
    KeysError(#[from] KeysError),
}
