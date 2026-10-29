use std::{path::Path, sync::Arc};

use keri_core::prefix::IdentifierPrefix;
use redb::{Database, TableDefinition};

use crate::error::ControllerError;

const PUBLISHED_RECEIPTS: TableDefinition<&str, u64> = TableDefinition::new("published_receipts");

/// The receipts already passed on to each witness.
pub struct IdentifierCache {
    db: Arc<Database>,
}

impl IdentifierCache {
    pub fn new(db_file: &Path) -> Result<Self, ControllerError> {
        let db = Database::create(db_file)?;
        Self::from_database(Arc::new(db))
    }

    /// Cache backed by redb's in-memory backend — nothing touches disk.
    pub fn new_in_memory() -> Result<Self, ControllerError> {
        let db = Database::builder()
            .create_with_backend(redb::backends::InMemoryBackend::new())
            .map_err(|e| ControllerError::CacheError(e.to_string()))?;
        Self::from_database(Arc::new(db))
    }

    /// Build on an already-open redb `Database` (file-backed or in-memory).
    pub fn from_database(db: Arc<Database>) -> Result<Self, ControllerError> {
        // Create tables if they don't exist
        let write_txn = db.begin_write()?;
        {
            write_txn.open_table(PUBLISHED_RECEIPTS)?;
        }
        write_txn.commit()?;
        Ok(Self { db })
    }

    /// Published receipts are tracked per (subject identifier, witness)
    /// pair: several identifiers can share one database (shared store
    /// layout), and keying on the witness alone would mix them up.
    fn composite_key(subject: &IdentifierPrefix, witness: &IdentifierPrefix) -> String {
        format!("{subject}|{witness}")
    }

    pub fn update_last_published_receipt(
        &self,
        subject: &IdentifierPrefix,
        witness: &IdentifierPrefix,
        sn: u64,
    ) -> Result<(), ControllerError> {
        let write_txn = self.db.begin_write()?;
        {
            let mut tbl = write_txn.open_table(PUBLISHED_RECEIPTS)?;
            tbl.insert(Self::composite_key(subject, witness).as_str(), sn)?;
        }
        write_txn.commit()?;
        Ok(())
    }

    pub fn load_published_receipts_sn(
        &self,
        subject: &IdentifierPrefix,
        witness: &IdentifierPrefix,
    ) -> Result<usize, ControllerError> {
        let read_txn = self.db.begin_read()?;
        let tbl = read_txn.open_table(PUBLISHED_RECEIPTS)?;
        let key = Self::composite_key(subject, witness);
        if let Some(value) = tbl.get(key.as_str())? {
            Ok(value.value() as usize)
        } else {
            Ok(0)
        }
    }
}

#[test]
fn published_receipts_are_kept_per_identifier_and_witness() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let cache = IdentifierCache::new(Path::new(tmp.path())).unwrap();
    let id: IdentifierPrefix = "BDg3H7Sr-eES0XWXiO8nvMxW6mD_1LxLeE1nuiZxhGp4"
        .parse()
        .unwrap();
    let other: IdentifierPrefix = "BP55jNfeiVfGn7-M5ugPCst9FlUOSaYourMDdxysMoX8"
        .parse()
        .unwrap();
    let witness: IdentifierPrefix = "BErocgXD2RGSyvn3MObcx59jeOsEQhv2TqHirVkzrp0Q"
        .parse()
        .unwrap();
    assert_eq!(cache.load_published_receipts_sn(&id, &witness).unwrap(), 0);
    cache.update_last_published_receipt(&id, &witness, 3).unwrap();
    assert_eq!(cache.load_published_receipts_sn(&id, &witness).unwrap(), 3);
    assert_eq!(cache.load_published_receipts_sn(&other, &witness).unwrap(), 0);
}
