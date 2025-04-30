use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

use serde::{Deserialize, Serialize};

#[cfg(feature = "mailbox")]
use super::mailbox::MailboxData;
use super::tables::SledEventTree;

#[cfg(feature = "mailbox")]
use crate::event_message::signed_event_message::SignedNontransferableReceipt;

use crate::{event_message::signed_event_message::SignedEventMessage, prefix::IdentifierPrefix};

use super::timestamped::TimestampedSignedEventMessage;

pub struct SledEventDatabase {
    db: Arc<sled::Db>,
    // // "iids" tree
    // this thing is expensive, but everything else is cheeeeeep
    identifiers: SledEventTree<IdentifierPrefix>,

    #[cfg(feature = "mailbox")]
    mailbox: MailboxData,
}

// TODO: remove all the `.ok()`s
impl SledEventDatabase {
    // pub fn new(path: impl AsRef<Path>) -> Result<Self, DbError> {
    //     let mut events_path = PathBuf::new();
    //     events_path.push(path);
    //     let mut escrow_path = events_path.clone();

    //     events_path.push("events");
    //     escrow_path.push("escrow");

    //     let db = Arc::new(sled::open(events_path.as_path())?);

    //     Ok(Self {
    //         identifiers: SledEventTree::new(db.open_tree(b"iids")?),
    //         #[cfg(feature = "mailbox")]
    //         mailbox: MailboxData::new(db.clone())?,
    //         db,
    //     })
    // }

    // #[cfg(feature = "mailbox")]
    // pub fn add_mailbox_receipt(
    //     &self,
    //     receipt: SignedNontransferableReceipt,
    //     id: &IdentifierPrefix,
    // ) -> Result<(), DbError> {
    //     self.mailbox
    //         .add_mailbox_receipt(self.identifiers.designated_key(id)?, receipt)?;
    //     self.db.flush()?;
    //     Ok(())
    // }

    // #[cfg(feature = "mailbox")]
    // pub fn get_mailbox_receipts(
    //     &self,
    //     id: &IdentifierPrefix,
    // ) -> Option<impl DoubleEndedIterator<Item = SignedNontransferableReceipt>> {
    //     self.mailbox
    //         .get_mailbox_receipts(self.identifiers.designated_key(id).ok()?)
    // }

    // #[cfg(feature = "mailbox")]
    // pub fn add_mailbox_reply(
    //     &self,
    //     reply: SignedEventMessage,
    //     id: &IdentifierPrefix,
    // ) -> Result<(), DbError> {
    //     self.mailbox
    //         .add_mailbox_reply(self.identifiers.designated_key(id)?, reply)?;
    //     self.db.flush()?;
    //     Ok(())
    // }

    // #[cfg(feature = "mailbox")]
    // pub fn get_mailbox_replies(
    //     &self,
    //     id: &IdentifierPrefix,
    // ) -> Option<impl DoubleEndedIterator<Item = SignedEventMessage>> {
    //     self.mailbox
    //         .get_mailbox_replies(self.identifiers.designated_key(id).ok()?)
    // }

    // #[cfg(feature = "mailbox")]
    // pub fn add_mailbox_multisig(
    //     &self,
    //     event: SignedEventMessage,
    //     target_id: &IdentifierPrefix,
    // ) -> Result<(), DbError> {
    //     self.mailbox
    //         .add_mailbox_multisig(self.identifiers.designated_key(target_id)?, event)?;
    //     self.db.flush()?;
    //     Ok(())
    // }

    // #[cfg(feature = "mailbox")]
    // pub fn get_mailbox_multisig(
    //     &self,
    //     id: &IdentifierPrefix,
    // ) -> Option<impl DoubleEndedIterator<Item = TimestampedSignedEventMessage>> {
    //     self.mailbox
    //         .get_mailbox_multisig(self.identifiers.designated_key(id).ok()?)
    // }

    // #[cfg(feature = "mailbox")]
    // pub fn add_mailbox_delegate(
    //     &self,
    //     event: SignedEventMessage,
    //     target_id: &IdentifierPrefix,
    // ) -> Result<(), DbError> {
    //     self.mailbox
    //         .add_mailbox_delegate(self.identifiers.designated_key(target_id)?, event)?;
    //     self.db.flush()?;
    //     Ok(())
    // }

    // #[cfg(feature = "mailbox")]
    // pub fn get_mailbox_delegate(
    //     &self,
    //     id: &IdentifierPrefix,
    // ) -> Option<impl DoubleEndedIterator<Item = TimestampedSignedEventMessage>> {
    //     self.mailbox
    //         .get_mailbox_delegate(self.identifiers.designated_key(id).ok()?)
    // }
}

#[derive(Debug, thiserror::Error, Serialize, Deserialize)]
pub enum DbError {
    // TODO: more variants
    #[error("sled error")]
    Sled,
    #[error("serde error")]
    Serde,
}

impl From<sled::Error> for DbError {
    fn from(_: sled::Error) -> Self {
        DbError::Sled
    }
}

impl From<serde_cbor::Error> for DbError {
    fn from(_: serde_cbor::Error) -> Self {
        DbError::Serde
    }
}
