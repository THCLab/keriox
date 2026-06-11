//! Store-level metadata database.
//!
//! Holds the non-secret bookkeeping that used to live in one file per field
//! under each alias directory (identifier prefixes, registry ids, group
//! membership, credential indexes, contact sources). One redb database per
//! store, created through the same [`StorageConfig`] as the event
//! databases — so an in-memory store keeps its metadata in memory too.
//!
//! Reads fall back to the legacy file layout and migrate the value into the
//! database, so stores written by older SDK versions (and dkms-bin) keep
//! working without an explicit migration step.

use std::path::Path;
use std::sync::Arc;

use redb::{Database, ReadableTable, TableDefinition};

use crate::advanced::error::{Error, Result};
use crate::advanced::types::StorageConfig;

/// `(alias, field) → value` — e.g. `("alice", "id") → "EJe6f…"`.
const ALIAS_META: TableDefinition<(&str, &str), &str> = TableDefinition::new("alias_meta");

pub(crate) struct MetaDb {
    db: Arc<Database>,
}

impl MetaDb {
    pub(crate) fn open(root: &Path, storage: &StorageConfig) -> Result<Self> {
        let db = match storage {
            StorageConfig::Redb => Database::create(root.join("meta"))
                .map_err(|e| Error::PersistenceError(format!("cannot open meta db: {e}")))?,
            StorageConfig::InMemory => Database::builder()
                .create_with_backend(redb::backends::InMemoryBackend::new())
                .map_err(|e| Error::PersistenceError(format!("cannot open meta db: {e}")))?,
        };
        // Make sure the table exists so reads on a fresh store don't error.
        let write_txn = db
            .begin_write()
            .map_err(|e| Error::PersistenceError(e.to_string()))?;
        write_txn
            .open_table(ALIAS_META)
            .map_err(|e| Error::PersistenceError(e.to_string()))?;
        write_txn
            .commit()
            .map_err(|e| Error::PersistenceError(e.to_string()))?;
        Ok(Self { db: Arc::new(db) })
    }

    pub(crate) fn get(&self, alias: &str, field: &str) -> Result<Option<String>> {
        let read_txn = self
            .db
            .begin_read()
            .map_err(|e| Error::PersistenceError(e.to_string()))?;
        let table = read_txn
            .open_table(ALIAS_META)
            .map_err(|e| Error::PersistenceError(e.to_string()))?;
        let value = table
            .get((alias, field))
            .map_err(|e| Error::PersistenceError(e.to_string()))?
            .map(|v| v.value().to_string());
        Ok(value)
    }

    pub(crate) fn set(&self, alias: &str, field: &str, value: &str) -> Result<()> {
        let write_txn = self
            .db
            .begin_write()
            .map_err(|e| Error::PersistenceError(e.to_string()))?;
        {
            let mut table = write_txn
                .open_table(ALIAS_META)
                .map_err(|e| Error::PersistenceError(e.to_string()))?;
            table
                .insert((alias, field), value)
                .map_err(|e| Error::PersistenceError(e.to_string()))?;
        }
        write_txn
            .commit()
            .map_err(|e| Error::PersistenceError(e.to_string()))
    }

    /// Distinct aliases that have at least one metadata entry.
    pub(crate) fn aliases(&self) -> Result<Vec<String>> {
        let read_txn = self
            .db
            .begin_read()
            .map_err(|e| Error::PersistenceError(e.to_string()))?;
        let table = read_txn
            .open_table(ALIAS_META)
            .map_err(|e| Error::PersistenceError(e.to_string()))?;
        let mut aliases: Vec<String> = vec![];
        for entry in table
            .iter()
            .map_err(|e| Error::PersistenceError(e.to_string()))?
        {
            let entry = entry.map_err(|e| Error::PersistenceError(e.to_string()))?;
            let (alias, _field) = entry.0.value();
            if aliases.last().map(String::as_str) != Some(alias) {
                aliases.push(alias.to_string());
            }
        }
        aliases.dedup();
        Ok(aliases)
    }
}
