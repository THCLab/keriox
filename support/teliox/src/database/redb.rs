use crate::{
    database::TelEventDatabase,
    error::Error,
    event::{verifiable_event::VerifiableEvent, Event},
};
use keri_core::prefix::IdentifierPrefix;
use redb::{Database, TableDefinition};
use sled_tables::{self};
use std::{path::Path, sync::Arc};

/// Events store. (event digest) -> tel event
/// The `EVENTS` table directly stores the event data, which other tables reference
/// by its digest.
const EVENTS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("events");

/// TEL events storage. (identifier, sn) -> event digest
/// The `VC_TELS` table links an identifier of VC and sequence number to the digest of an event,
/// referencing the actual event stored in the `EVENTS` table.
const VC_TELS: TableDefinition<(&str, u64), &[u8]> = TableDefinition::new("kels");

/// Management TEL events storage. (identifier, sn) -> event digest
/// The `MANAGEMENT TELS` table links an identifier of TEL and sequence number to the digest of an event,
/// referencing the actual event stored in the `EVENTS` table.
const MANAGEMENT_TELS: TableDefinition<(&str, u64), &[u8]> = TableDefinition::new("kels");

pub struct RedbTelDatabase {
    db: Arc<Database>,
}

impl TelEventDatabase for RedbTelDatabase {
    fn new(db_path: impl AsRef<Path>) -> Result<Self, Error> {
        let db = Arc::new(Database::create(db_path).unwrap());
        // Create tables
        let write_txn = db.begin_write()?;
        {
            write_txn.open_table(EVENTS)?;
            write_txn.open_table(VC_TELS)?;
            write_txn.open_table(MANAGEMENT_TELS)?;
        }
        write_txn.commit()?;
        Ok(Self { db })
    }

    fn add_new_event(&self, event: VerifiableEvent, id: &IdentifierPrefix) -> Result<(), Error> {
        let write_txn = self.db.begin_write()?;
        let key = event.get_event().get_digest().unwrap();
        {
            let mut table = write_txn.open_table(EVENTS)?;
            table.insert(
                key.to_string().as_bytes(),
                serde_cbor::to_vec(&event).unwrap().as_slice(),
            )?;
        }
        match event.event {
            Event::Management(typed_event) => {
                let id = typed_event.data.prefix.clone();
                let sn = typed_event.data.sn.clone();
                {
                    let mut man_tel_table = write_txn.open_table(MANAGEMENT_TELS)?;
                    man_tel_table
                        .insert((id.to_string().as_str(), sn), key.to_string().as_bytes())?;
                }
            }
            Event::Vc(typed_event) => {
                let id = typed_event.data.data.prefix.clone();
                let sn = typed_event.data.data.sn.clone();
                {
                    let mut man_tel_table = write_txn.open_table(VC_TELS)?;
                    man_tel_table
                        .insert((id.to_string().as_str(), sn), key.to_string().as_bytes())?;
                }
            }
        }
        write_txn.commit()?;

        Ok(())
    }

    fn get_events(
        &self,
        id: &IdentifierPrefix,
    ) -> Option<impl DoubleEndedIterator<Item = VerifiableEvent>> {
        let read_txn = self.db.begin_read().unwrap();
        let digests = {
            let table = read_txn.open_table(VC_TELS).unwrap();
            table
                .range((id.to_string().as_str(), 0)..(id.to_string().as_str(), u64::MAX))
                .unwrap()
        };

        let events_table = read_txn.open_table(EVENTS).unwrap();
        let out: Vec<_> = digests
            .filter_map(|entry| {
                let (_key, value) = entry.unwrap();
                let v = events_table.get(value.value()).unwrap();
                v.map(|v| {
                    let cbor_event = v.value().to_vec();
                    let event: VerifiableEvent = serde_cbor::from_slice(&cbor_event).unwrap();
                    event
                })
            })
            .collect();
        if out.is_empty() {
            None
        } else {
            Some(out.into_iter())
        }
    }

    fn add_new_management_event(
        &self,
        event: VerifiableEvent,
        id: &IdentifierPrefix,
    ) -> Result<(), Error> {
        let write_txn = self.db.begin_write()?;
        let key = event.get_event().get_digest().unwrap();
        {
            let mut table = write_txn.open_table(EVENTS)?;
            table.insert(
                key.to_string().as_bytes(),
                serde_cbor::to_vec(&event).unwrap().as_slice(),
            )?;
        }
        match event.event {
            Event::Management(typed_event) => {
                let id = typed_event.data.prefix.clone();
                let sn = typed_event.data.sn.clone();
                {
                    let mut man_tel_table = write_txn.open_table(MANAGEMENT_TELS)?;
                    man_tel_table
                        .insert((id.to_string().as_str(), sn), key.to_string().as_bytes())?;
                }
            }
            Event::Vc(typed_event) => {
                let id = typed_event.data.data.prefix.clone();
                let sn = typed_event.data.data.sn.clone();
                {
                    let mut man_tel_table = write_txn.open_table(VC_TELS)?;
                    man_tel_table
                        .insert((id.to_string().as_str(), sn), key.to_string().as_bytes())?;
                }
            }
        }
        write_txn.commit()?;
        Ok(())
    }

    fn get_management_events(
        &self,
        id: &IdentifierPrefix,
    ) -> Option<impl DoubleEndedIterator<Item = VerifiableEvent>> {
        let read_txn = self.db.begin_read().unwrap();
        let digests = {
            let table = read_txn.open_table(MANAGEMENT_TELS).unwrap();
            table
                .range((id.to_string().as_str(), 0)..(id.to_string().as_str(), u64::MAX))
                .unwrap()
        };

        let events_table = read_txn.open_table(EVENTS).unwrap();
        let out: Vec<_> = digests
            .filter_map(|entry| {
                let (_key, value) = entry.unwrap();
                let v = events_table.get(value.value()).unwrap();
                v.map(|v| {
                    let cbor_event = v.value().to_vec();
                    let event: VerifiableEvent = serde_cbor::from_slice(&cbor_event).unwrap();
                    event
                })
            })
            .collect();
        if out.is_empty() {None} else {
            Some(out.into_iter())
        }
    }
}
