use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Deserialize error: {0}")]
    DeserializeError(String),

    #[error(transparent)]
    ParseError(#[from] crate::event_parsing::error::Error),
}
