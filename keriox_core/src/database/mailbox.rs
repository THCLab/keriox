use sled::Db;

use crate::event_message::signed_event_message::{
    SignedEventMessage, SignedNontransferableReceipt,
};

use super::{tables::SledEventTreeVec, timestamped::TimestampedSignedEventMessage, DbError};

pub struct MailboxData {
    mailbox_receipts: SledEventTreeVec<SignedNontransferableReceipt>,
    mailbox_replies: SledEventTreeVec<SignedEventMessage>,
    mailbox_multisig: SledEventTreeVec<TimestampedSignedEventMessage>,
    mailbox_delegate: SledEventTreeVec<TimestampedSignedEventMessage>,
}

impl MailboxData {
    pub fn new(db: &Db) -> Result<Self, DbError> {
        Ok(Self {
            mailbox_receipts: SledEventTreeVec::new(db.open_tree(b"mbxrct")?),
            mailbox_replies: SledEventTreeVec::new(db.open_tree(b"mbxrpy")?),
            mailbox_multisig: SledEventTreeVec::new(db.open_tree(b"mbxm")?),
            mailbox_delegate: SledEventTreeVec::new(db.open_tree(b"mbxd")?),
        })
    }

    pub fn add_mailbox_receipt(
        &self,
        key: u64,
        receipt: SignedNontransferableReceipt,
    ) -> Result<(), DbError> {
        if !self.mailbox_receipts.contains_value(&receipt) {
            self.mailbox_receipts.push(key, receipt)
        } else {
            Ok(())
        }
    }

    pub fn get_mailbox_receipts(
        &self,
        key: u64,
    ) -> Option<impl DoubleEndedIterator<Item = SignedNontransferableReceipt>> {
        self.mailbox_receipts.iter_values(key)
    }

    pub fn add_mailbox_reply(&self, key: u64, reply: SignedEventMessage) -> Result<(), DbError> {
        if !self.mailbox_replies.contains_value(&reply) {
            self.mailbox_replies.push(key, reply)
        } else {
            Ok(())
        }
    }

    pub fn get_mailbox_replies(
        &self,
        key: u64,
    ) -> Option<impl DoubleEndedIterator<Item = SignedEventMessage>> {
        self.mailbox_replies.iter_values(key)
    }

    pub fn add_mailbox_multisig(&self, key: u64, event: SignedEventMessage) -> Result<(), DbError> {
        self.mailbox_multisig.push(key, event.into())
    }

    pub fn get_mailbox_multisig(
        &self,
        key: u64,
    ) -> Option<impl DoubleEndedIterator<Item = TimestampedSignedEventMessage>> {
        self.mailbox_multisig.iter_values(key)
    }

    pub fn add_mailbox_delegate(
        &self,
        key: u64,
        delegated: SignedEventMessage,
    ) -> Result<(), DbError> {
        self.mailbox_delegate.push(key, delegated.into())
    }

    pub fn get_mailbox_delegate(
        &self,
        key: u64,
    ) -> Option<impl DoubleEndedIterator<Item = TimestampedSignedEventMessage>> {
        self.mailbox_delegate.iter_values(key)
    }
}
