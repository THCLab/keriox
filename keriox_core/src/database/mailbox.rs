use std::{fmt::Debug, marker::PhantomData, sync::Arc};

use redb::{Database, TableDefinition};
use said::{
    derivation::{HashFunction, HashFunctionCode},
    SelfAddressingIdentifier,
};

use crate::{
    event_message::signed_event_message::{SignedEventMessage, SignedNontransferableReceipt},
    prefix::IdentifierPrefix,
};

use super::redb::{escrow_database::get_current_timestamp, RedbError};

/// Storage for elements in mailbox.
pub struct MailboxTopicDatabase<D: serde::Serialize + serde::de::DeserializeOwned> {
    db: Arc<Database>,
    table_name: String,
    _marker: PhantomData<D>,
    /// Escrowed events. (identifier, index) -> element serialized in cbor
    sn_key_table: TableDefinition<'static, (&'static str, u64), &'static [u8]>,
    /// Timestamps. (identifier, index) -> timestamp
    dts_table: TableDefinition<'static, (&'static str, u64), u64>,
    /// Next available indexes. (identifier, table_name) -> index
    indexes: TableDefinition<'static, (&'static str, &'static str), u64>,
}

impl<D: serde::Serialize + serde::de::DeserializeOwned + Debug> MailboxTopicDatabase<D> {
    pub fn new(db: Arc<Database>, table_name: &'static str) -> Result<Self, RedbError> {
        // Create tables
        let pse = TableDefinition::new(table_name);
        let indexes = TableDefinition::new("indexes");
        let dts = TableDefinition::new("timestamps_mailbox");

        let write_txn = db.begin_write()?;
        {
            write_txn.open_table(pse)?;
            write_txn.open_table(dts)?;
            write_txn.open_table(indexes)?;
        }
        write_txn.commit()?;
        Ok(Self {
            db,
            table_name: table_name.to_string(),
            _marker: PhantomData,
            indexes,
            sn_key_table: pse,
            dts_table: dts,
        })
    }

    pub fn insert(&self, identifier: &IdentifierPrefix, element: &D) -> Result<(), RedbError> {
        let read_txn = self.db.begin_read()?;
        let table = read_txn.open_table(self.indexes)?;
        let index = match table.get((identifier.to_string().as_str(), self.table_name.as_str()))? {
            Some(index) => index.value(),
            None => 0,
        };

        let write_txn = self.db.begin_write()?;

        {
            let mut table = (&write_txn).open_table(self.sn_key_table)?;
            let value = serde_cbor::to_vec(&element).unwrap();
            table.insert((identifier.to_string().as_str(), index), value.as_slice())?;

            let mut table = (&write_txn).open_table(self.dts_table)?;
            let value = get_current_timestamp();
            table.insert((identifier.to_string().as_str(), index), &value)?;

            let mut table = (&write_txn).open_table(self.indexes)?;
            table.insert(
                (identifier.to_string().as_str(), self.table_name.as_str()),
                &index + 1,
            )?;
        }
        write_txn.commit()?;
        Ok(())
    }

    pub fn get(&self, identifier: &IdentifierPrefix, sn: u64) -> Result<Option<D>, RedbError> {
        let read_txn = self.db.begin_read()?;
        let table = read_txn.open_table(self.sn_key_table)?;
        Ok(table
            .get((identifier.to_string().as_str(), sn))?
            .map(|value| serde_cbor::from_slice(value.value()).unwrap()))
    }

    pub fn get_grater_then(
        &self,
        identifier: &IdentifierPrefix,
        sn: u64,
    ) -> Result<impl DoubleEndedIterator<Item = D>, RedbError> {
        let read_txn = self.db.begin_read()?;
        let table = read_txn.open_table(self.sn_key_table)?;
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
                Ok((_key, value)) => Some(serde_cbor::from_slice::<D>(value.value()).unwrap()),
                _ => None,
            });

        Ok(out)
    }
}

#[test]
fn test_mailbox_topic_database() {
    use redb::Database;

    let temp_file = tempfile::NamedTempFile::new().unwrap();
    let db = Arc::new(Database::create(temp_file.path()).unwrap());
    let mailbox_db = MailboxTopicDatabase::<String>::new(db.clone(), "test_table").unwrap();

    let identifier = IdentifierPrefix::SelfAddressing(
        "EN41o7FSL2o9PfFps14ql7jxJ-4SYg4fYE-u143T6aFX"
            .parse::<SelfAddressingIdentifier>()
            .unwrap()
            .into(),
    );
    for i in 0..10 {
        let element = format!("test element {}", i);
        mailbox_db.insert(&identifier, &element).unwrap();
    }
    let fifth_elemet = mailbox_db.get(&identifier, 5).unwrap();
    assert_eq!(fifth_elemet, Some("test element 5".to_string()));
    let elements_from_fifth = mailbox_db.get_grater_then(&identifier, 5).unwrap();
    assert_eq!(
        elements_from_fifth.collect::<Vec<_>>(),
        vec![
            "test element 5".to_string(),
            "test element 6".to_string(),
            "test element 7".to_string(),
            "test element 8".to_string(),
            "test element 9".to_string()
        ]
    );
}

pub struct MailboxData {
    mailbox_receipts: MailboxTopicDatabase<SignedNontransferableReceipt>,
    mailbox_replies: MailboxTopicDatabase<SignedEventMessage>,
    mailbox_multisig: MailboxTopicDatabase<SelfAddressingIdentifier>,
    mailbox_delegate: MailboxTopicDatabase<SelfAddressingIdentifier>,
    log_db: MailboxLogDatabase,
}

impl MailboxData {
    pub fn new(db: Arc<Database>) -> Result<Self, RedbError> {
        let log_db = MailboxLogDatabase::new(db.clone())?;
        Ok(Self {
            mailbox_receipts: MailboxTopicDatabase::new(db.clone(), "mbxrct")?,
            mailbox_replies: MailboxTopicDatabase::new(db.clone(), "mbxrpy")?,
            mailbox_multisig: MailboxTopicDatabase::new(db.clone(), "mbxm")?,
            mailbox_delegate: MailboxTopicDatabase::new(db.clone(), "mbxd")?,
            log_db,
        })
    }

    pub fn add_mailbox_receipt(
        &self,
        key: &IdentifierPrefix,
        receipt: SignedNontransferableReceipt,
    ) -> Result<(), RedbError> {
        // TODO what if already is saved?
        self.mailbox_receipts.insert(key, &receipt)?;
        Ok(())
    }

    pub fn get_mailbox_receipts(
        &self,
        key: &IdentifierPrefix,
    ) -> Option<impl DoubleEndedIterator<Item = SignedNontransferableReceipt>> {
        Some(self.mailbox_receipts.get_grater_then(key, 0).unwrap())
    }

    pub fn add_mailbox_reply(
        &self,
        key: &IdentifierPrefix,
        reply: SignedEventMessage,
    ) -> Result<(), RedbError> {
        // TODO what if already is saved?
        self.mailbox_replies.insert(key, &reply)
    }

    pub fn get_mailbox_replies(
        &self,
        key: &IdentifierPrefix,
    ) -> Option<impl DoubleEndedIterator<Item = SignedEventMessage>> {
        Some(self.mailbox_replies.get_grater_then(key, 0).unwrap())
    }

    pub fn add_mailbox_multisig(
        &self,
        key: &IdentifierPrefix,
        event: SignedEventMessage,
    ) -> Result<(), RedbError> {
        let said = self.log_db.log_event(&event)?;
        self.mailbox_multisig.insert(key, &said)?;

        Ok(())
    }

    pub fn get_mailbox_multisig<'a>(
        &'a self,
        key: &IdentifierPrefix,
    ) -> Option<impl DoubleEndedIterator<Item = SignedEventMessage> + 'a> {
        let digests = self.mailbox_multisig.get_grater_then(key, 0).unwrap();
        Some(digests.map(|dig| self.log_db.get_event(&dig).unwrap()))
    }

    pub fn add_mailbox_delegate(
        &self,
        key: &IdentifierPrefix,
        delegated: SignedEventMessage,
    ) -> Result<(), RedbError> {
        let said = self.log_db.log_event(&delegated)?;
        self.mailbox_delegate.insert(key, &said)?;

        Ok(())
    }

    pub fn get_mailbox_delegate<'a>(
        &'a self,
        key: &IdentifierPrefix,
    ) -> Option<impl DoubleEndedIterator<Item = SignedEventMessage> + 'a> {
        let digests = self.mailbox_delegate.get_grater_then(key, 0).unwrap();
        Some(digests.map(|dig| self.log_db.get_event(&dig).unwrap()))
    }
}

const MAILBOX_LOG: TableDefinition<&[u8], &[u8]> = TableDefinition::new("mailbox_log");
/// Database for mailbox events.
pub(crate) struct MailboxLogDatabase {
    db: Arc<Database>,
}

impl MailboxLogDatabase {
    pub fn new(db: Arc<Database>) -> Result<Self, RedbError> {
        // Create tables
        let write_txn = db.begin_write()?;
        {
            write_txn.open_table(MAILBOX_LOG)?;
        }
        write_txn.commit()?;
        Ok(Self { db })
    }

    /// Saves event in database, if it wasn't already saved.
    /// Returns digest of added element, or None if event was already saved in database.
    pub fn log_event(
        &self,
        signed_event: &SignedEventMessage,
    ) -> Result<SelfAddressingIdentifier, RedbError> {
        let write_txn = self.db.begin_write()?;
        let digest = {
            let mut table = write_txn.open_table(MAILBOX_LOG)?;
            let digest = HashFunction::from(HashFunctionCode::Blake3_256)
                .derive(signed_event.encode().unwrap().as_slice());
            let value = serde_cbor::to_vec(signed_event).unwrap();
            table.insert(digest.to_string().as_bytes(), &value.as_ref())?;
            Ok(digest)
        };

        write_txn.commit()?;
        digest
    }

    pub fn get_event(&self, dig: &SelfAddressingIdentifier) -> Option<SignedEventMessage> {
        let read_txn = self.db.begin_read().unwrap();
        let table = read_txn.open_table(MAILBOX_LOG).unwrap();
        match table.get(dig.to_string().as_bytes()).unwrap() {
            Some(value) => {
                let event: SignedEventMessage = serde_cbor::from_slice(value.value()).unwrap();
                Some(event)
            }
            None => None,
        }
    }
}
