use std::{marker::PhantomData, sync::Arc};

use redb::{Database, TableDefinition};

use crate::{event_message::signed_event_message::{
    SignedEventMessage, SignedNontransferableReceipt,
}, prefix::IdentifierPrefix};

use super::{redb::{escrow_database::get_current_timestamp, RedbError}, sled::DbError, timestamped::TimestampedSignedEventMessage};


/// Storage for elements in mailbox.
pub struct MailboxTopicDatabase<D: serde::Serialize + serde::de::DeserializeOwned> {
    db: Arc<Database>,
    _marker: PhantomData<D>,
    /// Escrowed events. (identifier, sn) -> element serialized in cbor
    sn_key_table: TableDefinition<'static, (&'static str, u64), &'static [u8]>,
    /// Timestamps. (identifier, sn) -> timestamp
    dts_table: TableDefinition<'static, (&'static str, u64), u64>,
}

impl<D: serde::Serialize + serde::de::DeserializeOwned> MailboxTopicDatabase<D> {
    pub fn new(db: Arc<Database>, table_name: &'static str) -> Result<Self, RedbError> {
        // Create tables
        let pse = TableDefinition::new(table_name);
        let dts = TableDefinition::new("timestamps");

        let write_txn = db.begin_write()?;
        {
            write_txn.open_table(pse)?;
            write_txn.open_table(dts)?;
        }
        write_txn.commit()?;
        Ok(Self {
            db,
            _marker: PhantomData,
            sn_key_table: pse,
            dts_table: dts,
        })
    }

    pub fn insert(
        &self,
        identifier: &IdentifierPrefix,
        sn: u64,
        element: &D,
    ) -> Result<(), RedbError> {
        let write_txn = self.db.begin_write()?;
        {
            let mut table = (&write_txn).open_table(self.sn_key_table)?;
            let value = serde_cbor::to_vec(&element).unwrap();
            table.insert((identifier.to_string().as_str(), sn), value.as_slice())?;

            let mut table = (&write_txn).open_table(self.dts_table)?;
            let value = get_current_timestamp();
            table.insert((identifier.to_string().as_str(), sn), &value)?;
        }
        write_txn.commit()?;
        Ok(())
    }

    pub fn get(
        &self,
        identifier: &IdentifierPrefix,
        sn: u64,
    ) -> Result<Option<D>, RedbError> {
        let read_txn = self.db.begin_read()?;
        let table = read_txn.open_table(self.sn_key_table)?;
        Ok(table.get((identifier.to_string().as_str(), sn))?
            .map(|value| serde_cbor::from_slice(value.value()).unwrap()
            ))
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

pub struct MailboxData {
    db: Arc<Database>,
    mailbox_receipts: MailboxTopicDatabase<SignedNontransferableReceipt>,
    mailbox_replies: MailboxTopicDatabase<SignedEventMessage>,
    mailbox_multisig: MailboxTopicDatabase<TimestampedSignedEventMessage>,
    mailbox_delegate: MailboxTopicDatabase<TimestampedSignedEventMessage>,
}

impl MailboxData {
    pub fn new(db: Arc<Database>) -> Result<Self, DbError> {
        Ok(Self {
            mailbox_receipts: MailboxTopicDatabase::new(db.clone(), "mbxrct").unwrap(),
            mailbox_replies: MailboxTopicDatabase::new(db.clone(), "mbxrpy").unwrap(),
            mailbox_multisig: MailboxTopicDatabase::new(db.clone(),"mbxm").unwrap(),
            mailbox_delegate: MailboxTopicDatabase::new(db.clone(),"mbxd").unwrap(),
            db,
        })
    }

    pub fn add_mailbox_receipt(
        &self,
        key: &IdentifierPrefix,
        receipt: SignedNontransferableReceipt,
    ) -> Result<(), RedbError> {
        // TODO what if already is saved?
        self.mailbox_receipts.insert(key, 0, &receipt)?;
        Ok(())
    }

    pub fn get_mailbox_receipts(
        &self,
        key: &IdentifierPrefix,
    ) -> Option<impl DoubleEndedIterator<Item = SignedNontransferableReceipt>> {
        Some(self.mailbox_receipts.get_grater_then(key, 0).unwrap())
    }

    pub fn add_mailbox_reply(&self, key: &IdentifierPrefix, reply: SignedEventMessage) -> Result<(), RedbError> {
        // TODO what if already is saved?
        self.mailbox_replies.insert(key, 0, &reply)
    }

    pub fn get_mailbox_replies(
        &self,
        key: &IdentifierPrefix,
    ) -> Option<impl DoubleEndedIterator<Item = SignedEventMessage>> {
        Some(self.mailbox_replies.get_grater_then(key, 0).unwrap())
    }

    pub fn add_mailbox_multisig(&self, key: &IdentifierPrefix, event: SignedEventMessage) -> Result<(), RedbError> {
        self.mailbox_multisig.insert(key, 0, &event.into())
    }

    pub fn get_mailbox_multisig(
        &self,
        key: &IdentifierPrefix,
    ) -> Option<impl DoubleEndedIterator<Item = TimestampedSignedEventMessage>> {
        Some(self.mailbox_multisig.get_grater_then(key, 0).unwrap())
    }

    pub fn add_mailbox_delegate(
        &self,
        key: &IdentifierPrefix,
        delegated: SignedEventMessage,
    ) -> Result<(), RedbError> {
        self.mailbox_delegate.insert(key, 0, &delegated.into())?;
        Ok(())
    }

    pub fn get_mailbox_delegate(
        &self,
        key: &IdentifierPrefix,
    ) -> Option<impl DoubleEndedIterator<Item = TimestampedSignedEventMessage>> {
        Some(self.mailbox_delegate.get_grater_then(key, 0).unwrap())
    }
}
