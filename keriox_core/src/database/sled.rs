use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

use serde::{Deserialize, Serialize};

#[cfg(feature = "mailbox")]
use super::mailbox::MailboxData;
use super::tables::{SledEventTree, SledEventTreeVec};

#[cfg(feature = "mailbox")]
use crate::event_message::signed_event_message::SignedNontransferableReceipt;

#[cfg(feature = "query")]
use crate::query::reply_event::SignedReply;
use crate::{
    event::KeyEvent,
    event_message::{
        msg::KeriEvent, signed_event_message::SignedEventMessage, TimestampedEventMessage,
    },
    prefix::IdentifierPrefix,
};

use super::timestamped::TimestampedSignedEventMessage;

pub struct SledEventDatabase {
    db: Arc<sled::Db>,
    // // "iids" tree
    // this thing is expensive, but everything else is cheeeeeep
    identifiers: SledEventTree<IdentifierPrefix>,
    #[cfg(feature = "query")]
    accepted_rpy: SledEventTreeVec<SignedReply>,

    // "ldes" tree
    likely_duplicious_events: SledEventTreeVec<TimestampedEventMessage>,
    // "dels" tree
    duplicitous_events: SledEventTreeVec<TimestampedSignedEventMessage>,

    #[cfg(feature = "query")]
    escrowed_replys: SledEventTreeVec<SignedReply>,

    #[cfg(feature = "mailbox")]
    mailbox: MailboxData,
}

// TODO: remove all the `.ok()`s
impl SledEventDatabase {
    pub fn new(path: impl AsRef<Path>) -> Result<Self, DbError> {
        let mut events_path = PathBuf::new();
        events_path.push(path);
        let mut escrow_path = events_path.clone();

        events_path.push("events");
        escrow_path.push("escrow");

        let db = Arc::new(sled::open(events_path.as_path())?);

        Ok(Self {
            identifiers: SledEventTree::new(db.open_tree(b"iids")?),
            likely_duplicious_events: SledEventTreeVec::new(db.open_tree(b"ldes")?),
            duplicitous_events: SledEventTreeVec::new(db.open_tree(b"dels")?),
            #[cfg(feature = "query")]
            accepted_rpy: SledEventTreeVec::new(db.open_tree(b"knas")?),
            #[cfg(feature = "mailbox")]
            mailbox: MailboxData::new(db.clone())?,

            #[cfg(feature = "query")]
            escrowed_replys: SledEventTreeVec::new(db.open_tree(b"knes")?),
            db,
        })
    }

    pub fn add_likely_duplicious_event(
        &self,
        event: KeriEvent<KeyEvent>,
        id: &IdentifierPrefix,
    ) -> Result<(), DbError> {
        self.likely_duplicious_events
            .push(self.identifiers.designated_key(id)?, event.into())?;
        self.db.flush()?;
        Ok(())
    }

    pub fn get_likely_duplicitous_events(
        &self,
        id: &IdentifierPrefix,
    ) -> Option<impl DoubleEndedIterator<Item = TimestampedEventMessage>> {
        self.likely_duplicious_events
            .iter_values(self.identifiers.designated_key(id).ok()?)
    }

    pub fn add_duplicious_event(
        &self,
        event: SignedEventMessage,
        id: &IdentifierPrefix,
    ) -> Result<(), DbError> {
        self.duplicitous_events
            .push(self.identifiers.designated_key(id)?, event.into())
    }

    pub fn get_duplicious_events(
        &self,
        id: &IdentifierPrefix,
    ) -> Option<impl DoubleEndedIterator<Item = TimestampedSignedEventMessage>> {
        self.duplicitous_events
            .iter_values(self.identifiers.designated_key(id).ok()?)
    }

    #[cfg(feature = "query")]
    pub fn update_accepted_reply(
        &self,
        rpy: SignedReply,
        id: &IdentifierPrefix,
    ) -> Result<(), DbError> {
        use crate::query::reply_event::ReplyRoute;

        match self
            .accepted_rpy
            .iter_values(self.identifiers.designated_key(id)?)
        {
            Some(rpys) => {
                let filtered = rpys
                    .filter(|s| match (s.reply.get_route(), rpy.reply.get_route()) {
                        (ReplyRoute::Ksn(id1, _), ReplyRoute::Ksn(id2, _)) => id1 != id2,
                        _ => true,
                    })
                    .chain(Some(rpy.clone()).into_iter())
                    .collect();
                self.accepted_rpy
                    .put(self.identifiers.designated_key(id)?, filtered)
            }
            None => self
                .accepted_rpy
                .push(self.identifiers.designated_key(id)?, rpy),
        }?;
        self.db.flush()?;
        Ok(())
    }

    #[cfg(feature = "query")]
    pub fn get_accepted_replys(
        &self,
        id: &IdentifierPrefix,
    ) -> Option<impl DoubleEndedIterator<Item = SignedReply>> {
        self.accepted_rpy
            .iter_values(self.identifiers.designated_key(id).ok()?)
    }

    #[cfg(feature = "query")]
    pub fn remove_accepted_reply(
        &self,
        id: &IdentifierPrefix,
        rpy: SignedReply,
    ) -> Result<(), DbError> {
        self.accepted_rpy
            .remove(self.identifiers.designated_key(id)?, &rpy)?;
        self.db.flush()?;
        Ok(())
    }

    #[cfg(feature = "query")]
    pub fn add_escrowed_reply(
        &self,
        rpy: SignedReply,
        id: &IdentifierPrefix,
    ) -> Result<(), DbError> {
        self.escrowed_replys
            .push(self.identifiers.designated_key(id)?, rpy)?;
        self.db.flush()?;
        Ok(())
    }

    #[cfg(feature = "query")]
    pub fn get_escrowed_replys(
        &self,
        id: &IdentifierPrefix,
    ) -> Option<impl DoubleEndedIterator<Item = SignedReply>> {
        self.escrowed_replys
            .iter_values(self.identifiers.designated_key(id).ok()?)
    }

    #[cfg(feature = "query")]
    pub fn remove_escrowed_reply(
        &self,
        id: &IdentifierPrefix,
        rpy: &SignedReply,
    ) -> Result<(), DbError> {
        self.escrowed_replys
            .remove(self.identifiers.designated_key(id)?, rpy)?;
        self.db.flush()?;
        Ok(())
    }

    #[cfg(feature = "query")]
    pub fn get_all_escrowed_replys(&self) -> Option<impl DoubleEndedIterator<Item = SignedReply>> {
        self.escrowed_replys.get_all()
    }

    #[cfg(feature = "mailbox")]
    pub fn add_mailbox_receipt(
        &self,
        receipt: SignedNontransferableReceipt,
        id: &IdentifierPrefix,
    ) -> Result<(), DbError> {
        self.mailbox
            .add_mailbox_receipt(self.identifiers.designated_key(id)?, receipt)?;
        self.db.flush()?;
        Ok(())
    }

    #[cfg(feature = "mailbox")]
    pub fn get_mailbox_receipts(
        &self,
        id: &IdentifierPrefix,
    ) -> Option<impl DoubleEndedIterator<Item = SignedNontransferableReceipt>> {
        self.mailbox
            .get_mailbox_receipts(self.identifiers.designated_key(id).ok()?)
    }

    #[cfg(feature = "mailbox")]
    pub fn add_mailbox_reply(
        &self,
        reply: SignedEventMessage,
        id: &IdentifierPrefix,
    ) -> Result<(), DbError> {
        self.mailbox
            .add_mailbox_reply(self.identifiers.designated_key(id)?, reply)?;
        self.db.flush()?;
        Ok(())
    }

    #[cfg(feature = "mailbox")]
    pub fn get_mailbox_replies(
        &self,
        id: &IdentifierPrefix,
    ) -> Option<impl DoubleEndedIterator<Item = SignedEventMessage>> {
        self.mailbox
            .get_mailbox_replies(self.identifiers.designated_key(id).ok()?)
    }

    #[cfg(feature = "mailbox")]
    pub fn add_mailbox_multisig(
        &self,
        event: SignedEventMessage,
        target_id: &IdentifierPrefix,
    ) -> Result<(), DbError> {
        self.mailbox
            .add_mailbox_multisig(self.identifiers.designated_key(target_id)?, event)?;
        self.db.flush()?;
        Ok(())
    }

    #[cfg(feature = "mailbox")]
    pub fn get_mailbox_multisig(
        &self,
        id: &IdentifierPrefix,
    ) -> Option<impl DoubleEndedIterator<Item = TimestampedSignedEventMessage>> {
        self.mailbox
            .get_mailbox_multisig(self.identifiers.designated_key(id).ok()?)
    }

    #[cfg(feature = "mailbox")]
    pub fn add_mailbox_delegate(
        &self,
        event: SignedEventMessage,
        target_id: &IdentifierPrefix,
    ) -> Result<(), DbError> {
        self.mailbox
            .add_mailbox_delegate(self.identifiers.designated_key(target_id)?, event)?;
        self.db.flush()?;
        Ok(())
    }

    #[cfg(feature = "mailbox")]
    pub fn get_mailbox_delegate(
        &self,
        id: &IdentifierPrefix,
    ) -> Option<impl DoubleEndedIterator<Item = TimestampedSignedEventMessage>> {
        self.mailbox
            .get_mailbox_delegate(self.identifiers.designated_key(id).ok()?)
    }
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
