use serde::{Serialize, Deserialize};
use thiserror::Error;

#[derive(Error, Debug, Serialize, Deserialize)]
pub enum Error {
    #[error("Deserialize error: {0}")]
    DeserializeError(String),

    #[error(transparent)]
    ParseError(#[from] crate::event_parsing::error::Error),
}
