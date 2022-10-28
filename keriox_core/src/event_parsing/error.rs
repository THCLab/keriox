use base64::DecodeError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Base64 Decoding error")]
    Base64DecodingError {
        #[from]
        source: DecodeError,
    },
}
