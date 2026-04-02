use thiserror::Error;

#[derive(Debug, Error)]
pub enum KeyProviderError {
    #[error("key not found: {0}")]
    NotFound(String),

    #[error("key already exists: {0}")]
    AlreadyExists(String),

    #[error("unsupported operation: {0}")]
    UnsupportedOperation(String),

    #[error("authentication failed: {0}")]
    AuthenticationFailed(String),

    #[error("key is locked; call unlock() first")]
    Locked,

    #[error("encryption error: {0}")]
    EncryptionError(String),

    #[error("invalid key material: {0}")]
    InvalidKeyMaterial(String),

    #[error("unsupported algorithm: {0}")]
    UnsupportedAlgorithm(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("{0}")]
    Other(String),
}

impl KeyProviderError {
    pub(crate) fn unsupported(op: &str) -> Self {
        Self::UnsupportedOperation(op.into())
    }
}

pub type Result<T> = std::result::Result<T, KeyProviderError>;
