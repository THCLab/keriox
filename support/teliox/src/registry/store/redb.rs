//! Registries in a redb database.

use std::{path::Path, sync::Arc};

use redb::{Database, TableDefinition};
use said::SelfAddressingIdentifier;

use super::{block_from_text, block_to_text, RegistryStore};
use crate::registry::{BlindedState, RegistryError, RegistryMessage, Salt};

/// (registry, sn, event SAID) -> raw event body.
const EVENTS: TableDefinition<(&str, u64, &str), &[u8]> = TableDefinition::new("registry_events");

/// BLID -> the block as the CESR text of its group.
const BLOCKS: TableDefinition<&str, &str> = TableDefinition::new("registry_blocks");

/// registry -> qb64 salt.
const SALTS: TableDefinition<&str, &str> = TableDefinition::new("registry_salts");

pub struct RedbRegistryStore {
    db: Arc<Database>,
}

fn storage(e: impl std::fmt::Display) -> RegistryError {
    RegistryError::Storage(e.to_string())
}

impl RedbRegistryStore {
    pub fn new(path: &Path) -> Result<Self, RegistryError> {
        Self::with_database(Arc::new(Database::create(path).map_err(storage)?))
    }

    /// The store in a database shared with other tables.
    pub fn with_database(db: Arc<Database>) -> Result<Self, RegistryError> {
        let txn = db.begin_write().map_err(storage)?;
        {
            txn.open_table(EVENTS).map_err(storage)?;
            txn.open_table(BLOCKS).map_err(storage)?;
            txn.open_table(SALTS).map_err(storage)?;
        }
        txn.commit().map_err(storage)?;
        Ok(Self { db })
    }

    fn put<K: redb::Key + 'static, V: redb::Value + 'static>(
        &self,
        table: TableDefinition<K, V>,
        key: K::SelfType<'_>,
        value: V::SelfType<'_>,
    ) -> Result<(), RegistryError> {
        let txn = self.db.begin_write().map_err(storage)?;
        txn.open_table(table)
            .map_err(storage)?
            .insert(key, value)
            .map_err(storage)?;
        txn.commit().map_err(storage)
    }

    fn get_text(
        &self,
        table: TableDefinition<&str, &str>,
        key: &str,
    ) -> Result<Option<String>, RegistryError> {
        let txn = self.db.begin_read().map_err(storage)?;
        let table = txn.open_table(table).map_err(storage)?;
        Ok(table
            .get(key)
            .map_err(storage)?
            .map(|value| value.value().to_string()))
    }
}

impl RegistryStore for RedbRegistryStore {
    fn save_event(&self, event: &RegistryMessage) -> Result<(), RegistryError> {
        let (registry, said) = (event.registry()?.to_string(), event.said()?.to_string());
        self.put(
            EVENTS,
            (registry.as_str(), event.sn(), said.as_str()),
            event.encode()?.as_slice(),
        )
    }

    fn events(
        &self,
        registry: &SelfAddressingIdentifier,
    ) -> Result<Vec<RegistryMessage>, RegistryError> {
        let registry = registry.to_string();
        let txn = self.db.begin_read().map_err(storage)?;
        let table = txn.open_table(EVENTS).map_err(storage)?;
        let range = (registry.as_str(), 0, "")..=(registry.as_str(), u64::MAX, "~");
        table
            .range(range)
            .map_err(storage)?
            .map(|entry| RegistryMessage::parse(entry.map_err(storage)?.1.value()))
            .collect()
    }

    fn save_block(&self, block: &BlindedState) -> Result<(), RegistryError> {
        let blid = block.blid.to_string();
        self.put(BLOCKS, blid.as_str(), block_to_text(block)?.as_str())
    }

    fn block(
        &self,
        blid: &SelfAddressingIdentifier,
    ) -> Result<Option<BlindedState>, RegistryError> {
        self.get_text(BLOCKS, &blid.to_string())?
            .map(|text| block_from_text(&text))
            .transpose()
    }

    fn save_salt(
        &self,
        registry: &SelfAddressingIdentifier,
        salt: &Salt,
    ) -> Result<(), RegistryError> {
        let registry = registry.to_string();
        self.put(SALTS, registry.as_str(), salt.to_qb64().as_str())
    }

    fn salt(&self, registry: &SelfAddressingIdentifier) -> Result<Option<Salt>, RegistryError> {
        self.get_text(SALTS, &registry.to_string())?
            .map(|qb64| Salt::from_qb64(&qb64))
            .transpose()
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn the_redb_store_keeps_registries() {
        let path = tempfile::NamedTempFile::new().unwrap();
        let store = super::RedbRegistryStore::new(path.path()).unwrap();
        crate::registry::store::conformance::check(&store);
    }
}
