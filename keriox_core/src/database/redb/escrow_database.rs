use std::{
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use redb::{Database, MultimapTableDefinition, TableDefinition};
use said::SelfAddressingIdentifier;

use crate::prefix::IdentifierPrefix;

use super::{rkyv_adapter, RedbError};

/// Out Of Order Escrow. (identifier, sn) -> event digest
/// The `PSE` table links an identifier and sequence number to the digest of an event,
/// referencing the actual event stored in the `EVENTS` table in EventDatabase.
const PSE: MultimapTableDefinition<(&str, u64), &[u8]> =
    MultimapTableDefinition::new("out_of_order_escrow");

/// Timestamps. timestamp -> digest
/// The `TIME` table links a timestamp of when an event was saved in the database to the digest of an event.
const TIME: TableDefinition<u64, &[u8]> = TableDefinition::new("time");

/// Timestamps. digest -> timestamp
/// The `DTS` table links digest of an event witch time when an event was saved in the database.
const DTS: TableDefinition<&[u8], u64> = TableDefinition::new("timestamps");

/// Storage for digests of escrowed events.
/// The digest of an escrowed event can be used to retrieve the full event from the `LogDatabase`.  
/// The storage is indexed by a tuple of (identifier, sn), with the value being the event's digest.
pub struct SnKeyDatabase {
    db: Arc<Database>,
}

impl SnKeyDatabase {
    pub fn new(db: Arc<Database>) -> Result<Self, RedbError> {
        // Create tables
        let write_txn = db.begin_write()?;
        {
            write_txn.open_multimap_table(PSE)?;
            write_txn.open_table(DTS)?;
            write_txn.open_table(TIME)?;
        }
        write_txn.commit()?;
        Ok(Self { db })
    }

    pub fn insert(
        &self,
        identifier: &IdentifierPrefix,
        sn: u64,
        digest: &SelfAddressingIdentifier,
    ) -> Result<(), RedbError> {
        let write_txn = self.db.begin_write()?;
        {
            let mut table = (&write_txn).open_multimap_table(PSE)?;
            let value = rkyv_adapter::serialize_said(&digest)?;
            table.insert((identifier.to_string().as_str(), sn), value.as_ref())?;

            let mut table = (&write_txn).open_table(DTS)?;
            let value = get_current_timestamp();
            let key = rkyv_adapter::serialize_said(&digest)?;
            table.insert(key.as_slice(), &value)?;
        }
        write_txn.commit()?;
        Ok(())
    }

    pub fn get(
        &self,
        identifier: &IdentifierPrefix,
        sn: u64,
    ) -> Result<impl Iterator<Item = SelfAddressingIdentifier>, RedbError> {
        let read_txn = self.db.begin_read()?;
        let table = read_txn.open_multimap_table(PSE)?;
        let value = table.get((identifier.to_string().as_str(), sn))?;
        let out = value.filter_map(|value| match value {
            Ok(value) => {
                let said = rkyv_adapter::deserialize_said(value.value()).unwrap();
                Some(said)
            }
            _ => None,
        });
        Ok(out)
    }

    pub fn get_grater_then(
        &self,
        identifier: &IdentifierPrefix,
        sn: u64,
    ) -> Result<impl Iterator<Item = SelfAddressingIdentifier>, RedbError> {
        let read_txn = self.db.begin_read()?;
        let table = read_txn.open_multimap_table(PSE)?;
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
                Ok((_key, value)) => Some(value.filter_map(|value| match value {
                    Ok(value) => {
                        let said = rkyv_adapter::deserialize_said(value.value()).unwrap();
                        Some(said)
                    }
                    Err(_) => None,
                })),
                _ => None,
            })
            .flatten();

        Ok(out)
    }

    pub fn remove(
        &self,
        identifier: &IdentifierPrefix,
        sn: u64,
        said: &SelfAddressingIdentifier,
    ) -> Result<(), RedbError> {
        let write_txn = self.db.begin_write()?;
        {
            let mut table = write_txn.open_multimap_table(PSE)?;
            let said = rkyv_adapter::serialize_said(said).unwrap();
            table.remove((identifier.to_string().as_str(), sn), said.as_slice())?;

            let mut table = write_txn.open_table(DTS)?;
            table.remove(said.as_slice())?;
        }

        write_txn.commit()?;
        Ok(())
    }
}

fn get_current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs()
}
