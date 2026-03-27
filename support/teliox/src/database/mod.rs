use crate::{error::Error, event::verifiable_event::VerifiableEvent};
use keri_core::prefix::IdentifierPrefix;
#[cfg(feature = "storage-redb")]
use said::SelfAddressingIdentifier;
use std::path::Path;

#[cfg(feature = "storage-redb")]
pub(crate) mod digest_key_database;
#[cfg(feature = "storage-redb")]
pub mod redb;

pub trait TelEventDatabase {
    fn new(path: impl AsRef<Path>) -> Result<Self, Error>
    where
        Self: Sized;

    fn add_new_event(&self, event: VerifiableEvent, id: &IdentifierPrefix) -> Result<(), Error>;

    fn get_events(
        &self,
        id: &IdentifierPrefix,
    ) -> Option<impl DoubleEndedIterator<Item = VerifiableEvent>>;

    fn get_management_events(
        &self,
        id: &IdentifierPrefix,
    ) -> Option<impl DoubleEndedIterator<Item = VerifiableEvent>>;
}

#[cfg(feature = "storage-redb")]
pub trait TelLogDatabase {
    fn log_event(
        &self,
        event: &VerifiableEvent,
        transaction: &keri_core::database::redb::WriteTxnMode,
    ) -> Result<(), Error>;
    fn get(&self, digest: &SelfAddressingIdentifier) -> Result<Option<VerifiableEvent>, Error>;
}

#[cfg(feature = "storage-redb")]
pub struct EscrowDatabase(pub(crate) std::sync::Arc<::redb::Database>);

#[cfg(feature = "storage-redb")]
impl EscrowDatabase {
    pub fn new(file_path: &Path) -> Result<Self, Error> {
        use std::fs::{create_dir_all, exists};
        // Create file if not exists
        if !std::fs::exists(file_path).map_err(|e| Error::EscrowDatabaseError(e.to_string()))? {
            if let Some(parent) = file_path.parent() {
                if !exists(parent).map_err(|e| Error::EscrowDatabaseError(e.to_string()))? {
                    create_dir_all(parent)
                        .map_err(|e| Error::EscrowDatabaseError(e.to_string()))?;
                }
            }
        }
        let db = ::redb::Database::create(file_path)
            .map_err(|e| Error::EscrowDatabaseError(e.to_string()))?;
        Ok(Self(std::sync::Arc::new(db)))
    }
}
