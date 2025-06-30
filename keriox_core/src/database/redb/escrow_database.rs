use std::{
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use redb::{Database, MultimapTableDefinition, TableDefinition};
use said::SelfAddressingIdentifier;

use crate::{database::SequencedEventDatabase, prefix::IdentifierPrefix};

use super::{rkyv_adapter, RedbError};

/// Storage for digests of escrowed events.
/// The digest of an escrowed event can be used to retrieve the full event from the `LogDatabase`.  
/// The storage is indexed by a tuple of (identifier, sn), with the value being the event's digest.
pub struct SnKeyDatabase {
    db: Arc<Database>,
    /// Escrowed events. (identifier, sn) -> event digest
    /// Table links an identifier and sequence number to the digest of an event,
    /// referencing the actual event stored in the `EVENTS` table in EventDatabase.
    sn_key_table:
        MultimapTableDefinition<'static, (&'static str, u64), &'static [u8]>,
    /// Timestamps. digest -> timestamp
    /// Table links digest of an event witch time when an event was saved in the database.
    dts_table: TableDefinition<'static, &'static [u8], u64>,
}

impl SequencedEventDatabase for SnKeyDatabase {
    type DatabaseType = redb::Database;
    type Error = RedbError;
    type DigestIter = Box<dyn Iterator<Item = SelfAddressingIdentifier>>;

    fn new(
        db: Arc<Self::DatabaseType>,
        table_name: &'static str,
    ) -> Result<Self, RedbError> {
        // Create tables
        let pse = MultimapTableDefinition::new(table_name);
        let dts = TableDefinition::new("timestamps_escrow");

        let write_txn = db.begin_write()?;
        {
            write_txn.open_multimap_table(pse)?;
            write_txn.open_table(dts)?;
        }
        write_txn.commit()?;
        Ok(Self {
            db,
            sn_key_table: pse,
            dts_table: dts,
        })
    }

    fn insert(
        &self,
        identifier: &IdentifierPrefix,
        sn: u64,
        digest: &SelfAddressingIdentifier,
    ) -> Result<(), RedbError> {
        let write_txn = self.db.begin_write()?;
        {
            let mut table =
                (&write_txn).open_multimap_table(self.sn_key_table)?;
            let value = rkyv_adapter::serialize_said(&digest)?;
            table.insert(
                (identifier.to_string().as_str(), sn),
                value.as_ref(),
            )?;

            let mut table = (&write_txn).open_table(self.dts_table)?;
            let value = get_current_timestamp();
            let key = rkyv_adapter::serialize_said(&digest)?;
            table.insert(key.as_slice(), &value)?;
        }
        write_txn.commit()?;
        Ok(())
    }

    fn get(
        &self,
        identifier: &IdentifierPrefix,
        sn: u64,
    ) -> Result<Self::DigestIter, RedbError> {
        let read_txn = self.db.begin_read()?;
        let table = read_txn.open_multimap_table(self.sn_key_table)?;
        let value = table.get((identifier.to_string().as_str(), sn))?;
        let out = value.filter_map(|value| match value {
            Ok(value) => {
                let said =
                    rkyv_adapter::deserialize_said(value.value()).unwrap();
                Some(said)
            }
            _ => None,
        });
        Ok(Box::new(out))
    }

    fn get_greater_than(
        &self,
        identifier: &IdentifierPrefix,
        sn: u64,
    ) -> Result<Self::DigestIter, RedbError> {
        let read_txn = self.db.begin_read()?;
        let table = read_txn.open_multimap_table(self.sn_key_table)?;
        let lower_bound = identifier.to_string();
        let upper_bound = {
            let mut bytes = lower_bound.as_bytes().to_vec();
            if let Some(last) = bytes.last_mut() {
                *last += 1; // Increment the last byte to get the next lexicographic string
            };
            String::from_utf8(bytes).unwrap()
        };
        let out = table
            .range((lower_bound.as_str(), sn)..(upper_bound.as_str(), 0))?
            .filter_map(|range| match range {
                Ok((_key, value)) => {
                    Some(value.filter_map(|value| match value {
                        Ok(value) => {
                            let said =
                                rkyv_adapter::deserialize_said(value.value())
                                    .unwrap();
                            Some(said)
                        }
                        Err(_) => None,
                    }))
                }
                _ => None,
            })
            .flatten();

        Ok(Box::new(out))
    }

    fn remove(
        &self,
        identifier: &IdentifierPrefix,
        sn: u64,
        said: &SelfAddressingIdentifier,
    ) -> Result<(), RedbError> {
        let write_txn = self.db.begin_write()?;
        {
            let mut table = write_txn.open_multimap_table(self.sn_key_table)?;
            let said = rkyv_adapter::serialize_said(said).unwrap();
            table.remove(
                (identifier.to_string().as_str(), sn),
                said.as_slice(),
            )?;

            let mut table = write_txn.open_table(self.dts_table)?;
            table.remove(said.as_slice())?;
        }

        write_txn.commit()?;
        Ok(())
    }
}

pub(crate) fn get_current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs()
}
