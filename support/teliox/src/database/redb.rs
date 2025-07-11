use crate::{
    database::{TelEventDatabase, TelLogDatabase},
    error::Error,
    event::{
        manager_event::ManagerTelEventMessage, vc_event::VCEventMessage,
        verifiable_event::VerifiableEvent, Event,
    },
};
use keri_core::{
    database::redb::{execute_in_transaction, WriteTxnMode},
    prefix::IdentifierPrefix,
};
use redb::{Database, ReadTransaction, TableDefinition};
use std::{fs, path::Path, sync::Arc};

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
    events_log: Arc<LogTelDb>,
    tel_digests: Arc<TelEventsDb>,
    db: Arc<Database>,
}

pub struct TelEventsDb {
    db: Arc<Database>,
}

impl TelEventsDb {
    pub fn new(db: Arc<Database>) -> Result<Self, Error> {
        // Create tables
        let write_txn = db.begin_write()?;
        {
            write_txn.open_table(VC_TELS)?;
            write_txn.open_table(MANAGEMENT_TELS)?;
        }
        write_txn.commit()?;
        Ok(Self { db })
    }

    fn add_vc_event_digest(
        &self,
        vc_event: VCEventMessage,
        txn_mode: &WriteTxnMode,
    ) -> Result<(), Error> {
        let id = vc_event.data.data.prefix.clone();
        let sn = vc_event.data.data.sn.clone();
        let said = vc_event
            .digest()
            .map_err(|_e| Error::Generic("Event does not have a digest".to_string()))?;
        execute_in_transaction(self.db.clone(), txn_mode, |write_txn| {
            {
                let mut man_tel_table = write_txn.open_table(VC_TELS)?;
                man_tel_table.insert((id.to_string().as_str(), sn), said.to_string().as_bytes())?;
            };
            Ok(())
        })
        .map_err(|e| Error::Generic(format!("Failed to insert digest: {}", e)))
    }

    fn add_management_event_digest(
        &self,
        vc_event: ManagerTelEventMessage,
        txn_mode: &WriteTxnMode,
    ) -> Result<(), Error> {
        let id = vc_event.data.prefix.clone();
        let sn = vc_event.data.sn.clone();
        let said = vc_event
            .digest()
            .map_err(|_e| Error::Generic("Event does not have a digest".to_string()))?;
        execute_in_transaction(self.db.clone(), txn_mode, |write_txn| {
            {
                let mut man_tel_table = write_txn.open_table(MANAGEMENT_TELS)?;
                man_tel_table.insert((id.to_string().as_str(), sn), said.to_string().as_bytes())?;
            };
            Ok(())
        })
        .map_err(|e| Error::Generic(format!("Failed to insert digest: {}", e)))
    }

    pub fn get_vc_events(
        &self,
        id: &IdentifierPrefix,
        txn: &ReadTransaction,
    ) -> impl Iterator<Item = Vec<u8>> {
        let table = txn.open_table(VC_TELS).unwrap();
        table
            .range((id.to_string().as_str(), 0)..(id.to_string().as_str(), u64::MAX))
            .unwrap()
            .map(|entry| {
                // let (_key, value) = entry.unwrap();
                entry.unwrap().1.value().to_vec()
            })
    }

    pub fn get_management_events(
        &self,
        id: &IdentifierPrefix,
        txn: &ReadTransaction,
    ) -> impl Iterator<Item = Vec<u8>> {
        let table = txn.open_table(MANAGEMENT_TELS).unwrap();
        table
            .range((id.to_string().as_str(), 0)..(id.to_string().as_str(), u64::MAX))
            .unwrap()
            .map(|entry| {
                // let (_key, value) = entry.unwrap();
                entry.unwrap().1.value().to_vec()
            })
    }
}

pub struct LogTelDb {
    db: Arc<Database>,
}

impl LogTelDb {
    pub fn new(db: Arc<Database>) -> Result<Self, Error> {
        // Create tables
        let write_txn = db.begin_write()?;
        {            
            write_txn.open_table(EVENTS)?;
        }
        write_txn.commit()?;
        Ok(Self { db })
    }

    /// Saves provided event into key event table. Key is it's digest and value is event.
    fn log_event(&self, event: &VerifiableEvent, transaction: &WriteTxnMode) -> Result<(), Error> {
        let digest = event
            .event
            .get_digest()
            .map_err(|_e| Error::Generic("Event does not have a digest".to_string()))?;
        let value = serde_cbor::to_vec(&event)
            .map_err(|_e| Error::Generic("Failed to serialize event".to_string()))?;

        execute_in_transaction(self.db.clone(), transaction, |write_txn| {
            let mut table = write_txn.open_table(EVENTS)?;
            let key = digest.to_string();
            table.insert(key.as_bytes(), &value.as_ref())?;
            Ok(())
        })
        .map_err(|e| Error::Generic(format!("Failed to log event: {}", e)))
    }

    fn get(
        &self,
        digest: &said::SelfAddressingIdentifier,
    ) -> Result<Option<VerifiableEvent>, Error> {
        let read_txn = self.db.begin_read()?;
        let table = read_txn.open_table(EVENTS)?;
        if let Some(value) = table.get(digest.to_string().as_bytes())? {
            let cbor_event = value.value().to_vec();
            let event: VerifiableEvent = serde_cbor::from_slice(&cbor_event).unwrap();
            Ok(Some(event))
        } else {
            Ok(None)
        }
    }

    fn get_by_serialized_key(&self, digest: &[u8]) -> Result<Option<VerifiableEvent>, Error> {
        let read_txn = self.db.begin_read()?;
        let table = read_txn.open_table(EVENTS)?;
        if let Some(value) = table.get(digest)? {
            let cbor_event = value.value().to_vec();
            let event: VerifiableEvent = serde_cbor::from_slice(&cbor_event).unwrap();
            Ok(Some(event))
        } else {
            Ok(None)
        }
    }
}

impl TelLogDatabase for RedbTelDatabase {
    /// Saves provided event. Key is it's digest and value is event.
    fn log_event(&self, event: &VerifiableEvent, transaction: &WriteTxnMode) -> Result<(), Error> {
        self.events_log.log_event(event, transaction)
    }

    fn get(
        &self,
        digest: &said::SelfAddressingIdentifier,
    ) -> Result<Option<VerifiableEvent>, Error> {
        self.events_log.get(digest)
    }
}

impl TelEventDatabase for RedbTelDatabase {
    fn new(db_path: impl AsRef<Path>) -> Result<Self, Error> {
        if let Some(parent) = db_path.as_ref().parent() {
            fs::create_dir_all(parent).unwrap();
        }
        let db = Arc::new(Database::create(db_path).unwrap());
        let log = Arc::new(LogTelDb::new(db.clone())?);
        let events_db = TelEventsDb::new(db.clone())?;
        Ok(Self {
            events_log: log,
            tel_digests: Arc::new(events_db),
            db,
        })
    }

    fn add_new_event(&self, event: VerifiableEvent, id: &IdentifierPrefix) -> Result<(), Error> {
        let write_txn = self.db.begin_write()?;
        let txn_mode = WriteTxnMode::UseExisting(&write_txn);
        self.events_log.log_event(&event, &txn_mode)?;

        match event.event {
            Event::Management(typed_event) => {
                self.tel_digests
                    .add_management_event_digest(typed_event, &txn_mode)?;
            }
            Event::Vc(typed_event) => {
                self.tel_digests
                    .add_vc_event_digest(typed_event, &txn_mode)?;
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
        let digests = self.tel_digests.get_vc_events(id, &read_txn);

        let mut out_iter = digests
            .filter_map(|entry| self.events_log.get_by_serialized_key(&entry).unwrap())
            .peekable();
        if out_iter.peek().is_none() {
            None
        } else {
            Some(out_iter.collect::<Vec<_>>().into_iter())
        }
    }


    fn get_management_events(
        &self,
        id: &IdentifierPrefix,
    ) -> Option<impl DoubleEndedIterator<Item = VerifiableEvent>> {
        let read_txn = self.db.begin_read().unwrap();
        let digests = self.tel_digests.get_management_events(id, &read_txn);

        let mut out_iter = digests
            .filter_map(|entry| self.events_log.get_by_serialized_key(&entry).unwrap())
            .peekable();
        if out_iter.peek().is_none() {
            None
        } else {
            Some(out_iter.collect::<Vec<_>>().into_iter())
        }
    }
}
