use crate::{error::Error, event::verifiable_event::VerifiableEvent};
use keri_core::prefix::IdentifierPrefix;
use said::SelfAddressingIdentifier;

#[cfg(feature = "storage-redb")]
pub(crate) mod digest_key_database;
#[cfg(feature = "storage-postgres")]
pub mod postgres;
#[cfg(feature = "storage-redb")]
pub mod redb;

pub trait TelEventDatabase: Send + Sync {
    fn add_new_event(&self, event: VerifiableEvent, id: &IdentifierPrefix) -> Result<(), Error>;

    fn get_events(
        &self,
        id: &IdentifierPrefix,
    ) -> Option<impl DoubleEndedIterator<Item = VerifiableEvent>>;

    fn get_management_events(
        &self,
        id: &IdentifierPrefix,
    ) -> Option<impl DoubleEndedIterator<Item = VerifiableEvent>>;

    fn log_event(&self, event: &VerifiableEvent) -> Result<(), Error>;

    fn get_event(
        &self,
        digest: &SelfAddressingIdentifier,
    ) -> Result<Option<VerifiableEvent>, Error>;
}

pub trait TelEscrowDatabase: Send + Sync {
    fn missing_issuer_insert(
        &self,
        kel_digest: &str,
        tel_digest: &SelfAddressingIdentifier,
    ) -> Result<(), Error>;

    fn missing_issuer_get(&self, kel_digest: &str) -> Result<Vec<SelfAddressingIdentifier>, Error>;

    fn missing_issuer_remove(
        &self,
        kel_digest: &str,
        tel_digest: &SelfAddressingIdentifier,
    ) -> Result<(), Error>;

    fn out_of_order_insert(
        &self,
        id: &IdentifierPrefix,
        sn: u64,
        digest: &SelfAddressingIdentifier,
    ) -> Result<(), Error>;

    fn out_of_order_get(
        &self,
        id: &IdentifierPrefix,
        sn: u64,
    ) -> Result<Vec<SelfAddressingIdentifier>, Error>;

    fn out_of_order_remove(
        &self,
        id: &IdentifierPrefix,
        sn: u64,
        digest: &SelfAddressingIdentifier,
    ) -> Result<(), Error>;

    fn missing_registry_insert(
        &self,
        registry_id: &str,
        digest: &SelfAddressingIdentifier,
    ) -> Result<(), Error>;

    fn missing_registry_get(
        &self,
        registry_id: &str,
    ) -> Result<Vec<SelfAddressingIdentifier>, Error>;

    fn missing_registry_remove(
        &self,
        registry_id: &str,
        digest: &SelfAddressingIdentifier,
    ) -> Result<(), Error>;
}

#[cfg(feature = "storage-redb")]
pub struct EscrowDatabase {
    missing_issuer: digest_key_database::DigestKeyDatabase,
    out_of_order: keri_core::database::redb::escrow_database::SnKeyDatabase,
    missing_registry: digest_key_database::DigestKeyDatabase,
}

#[cfg(feature = "storage-redb")]
impl EscrowDatabase {
    pub fn new(file_path: &std::path::Path) -> Result<Self, Error> {
        use std::fs::{create_dir_all, exists};
        if !std::fs::exists(file_path).map_err(|e| Error::EscrowDatabaseError(e.to_string()))? {
            if let Some(parent) = file_path.parent() {
                if !exists(parent).map_err(|e| Error::EscrowDatabaseError(e.to_string()))? {
                    create_dir_all(parent)
                        .map_err(|e| Error::EscrowDatabaseError(e.to_string()))?;
                }
            }
        }
        let db = std::sync::Arc::new(
            ::redb::Database::create(file_path)
                .map_err(|e| Error::EscrowDatabaseError(e.to_string()))?,
        );
        Self::from_database(db)
    }

    /// Escrow database backed by redb's in-memory backend — nothing touches
    /// disk; state lives exactly as long as this instance.
    pub fn new_in_memory() -> Result<Self, Error> {
        let db = std::sync::Arc::new(
            ::redb::Database::builder()
                .create_with_backend(::redb::backends::InMemoryBackend::new())
                .map_err(|e| Error::EscrowDatabaseError(e.to_string()))?,
        );
        Self::from_database(db)
    }

    /// Build on an already-open redb `Database` (file-backed or in-memory).
    pub fn from_database(db: std::sync::Arc<::redb::Database>) -> Result<Self, Error> {
        use keri_core::database::SequencedEventDatabase;
        let missing_issuer =
            digest_key_database::DigestKeyDatabase::new(db.clone(), "missing_issuer_escrow");
        let out_of_order = keri_core::database::redb::escrow_database::SnKeyDatabase::new(
            db.clone(),
            "out_of_order",
        )
        .map_err(|e| Error::EscrowDatabaseError(e.to_string()))?;
        let missing_registry =
            digest_key_database::DigestKeyDatabase::new(db, "missing_registry_escrow");

        Ok(Self {
            missing_issuer,
            out_of_order,
            missing_registry,
        })
    }
}

#[cfg(feature = "storage-redb")]
impl TelEscrowDatabase for EscrowDatabase {
    fn missing_issuer_insert(
        &self,
        kel_digest: &str,
        tel_digest: &SelfAddressingIdentifier,
    ) -> Result<(), Error> {
        self.missing_issuer.insert(&kel_digest, tel_digest)
    }

    fn missing_issuer_get(&self, kel_digest: &str) -> Result<Vec<SelfAddressingIdentifier>, Error> {
        self.missing_issuer.get(&kel_digest)
    }

    fn missing_issuer_remove(
        &self,
        kel_digest: &str,
        tel_digest: &SelfAddressingIdentifier,
    ) -> Result<(), Error> {
        self.missing_issuer.remove(&kel_digest, tel_digest)
    }

    fn out_of_order_insert(
        &self,
        id: &IdentifierPrefix,
        sn: u64,
        digest: &SelfAddressingIdentifier,
    ) -> Result<(), Error> {
        use keri_core::database::SequencedEventDatabase;
        self.out_of_order
            .insert(id, sn, digest)
            .map_err(|e| Error::EscrowDatabaseError(e.to_string()))
    }

    fn out_of_order_get(
        &self,
        id: &IdentifierPrefix,
        sn: u64,
    ) -> Result<Vec<SelfAddressingIdentifier>, Error> {
        use keri_core::database::SequencedEventDatabase;
        let iter = self
            .out_of_order
            .get(id, sn)
            .map_err(|e| Error::EscrowDatabaseError(e.to_string()))?;
        Ok(iter.collect())
    }

    fn out_of_order_remove(
        &self,
        id: &IdentifierPrefix,
        sn: u64,
        digest: &SelfAddressingIdentifier,
    ) -> Result<(), Error> {
        use keri_core::database::SequencedEventDatabase;
        self.out_of_order
            .remove(id, sn, digest)
            .map_err(|e| Error::EscrowDatabaseError(e.to_string()))
    }

    fn missing_registry_insert(
        &self,
        registry_id: &str,
        digest: &SelfAddressingIdentifier,
    ) -> Result<(), Error> {
        self.missing_registry.insert(&registry_id, digest)
    }

    fn missing_registry_get(
        &self,
        registry_id: &str,
    ) -> Result<Vec<SelfAddressingIdentifier>, Error> {
        self.missing_registry.get(&registry_id)
    }

    fn missing_registry_remove(
        &self,
        registry_id: &str,
        digest: &SelfAddressingIdentifier,
    ) -> Result<(), Error> {
        self.missing_registry.remove(&registry_id, digest)
    }
}
