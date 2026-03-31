#[derive(Debug, thiserror::Error)]
pub enum PostgresError {
    #[error("Database error: {0}")]
    Sqlx(#[from] sqlx::Error),
    #[error("Migration error: {0}")]
    Migration(#[from] sqlx::migrate::MigrateError),
    #[error("Rkyv serialization error: {0}")]
    Rkyv(#[from] rkyv::rancor::Error),
    #[error("CBOR error: {0}")]
    Cbor(#[from] serde_cbor::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("No event for digest {0} found")]
    NotFound(said::SelfAddressingIdentifier),
    #[error("No digest in provided event")]
    MissingDigest,
    #[error("Already saved: {0}")]
    AlreadySaved(said::SelfAddressingIdentifier),
}
