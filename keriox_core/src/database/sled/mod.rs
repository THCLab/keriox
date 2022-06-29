pub(crate) mod tables;

use std::path::{Path, PathBuf};

use self::tables::{SledEventTree, SledEventTreeVec};
#[cfg(feature = "query")]
use crate::query::reply_event::SignedReply;
use crate::{
    event::EventMessage,
    event_message::{
        key_event_message::KeyEvent,
        signed_event_message::{
            SignedEventMessage, SignedNontransferableReceipt, SignedTransferableReceipt,
            TimestampedSignedEventMessage,
        },
        TimestampedEventMessage,
    },
    prefix::IdentifierPrefix,
};

pub struct SledEventDatabase {
    // "iids" tree
    // this thing is expensive, but everything else is cheeeeeep
    identifiers: SledEventTree<IdentifierPrefix>,
    // "kels" tree
    key_event_logs: SledEventTreeVec<TimestampedSignedEventMessage>,
    // "ooes" tree
    escrowed_out_of_order: SledEventTreeVec<TimestampedSignedEventMessage>,
    // "pses" tree
    escrowed_partially_signed: SledEventTreeVec<TimestampedSignedEventMessage>,
    // "ldes" tree
    likely_duplicious_events: SledEventTreeVec<TimestampedEventMessage>,
    // "dels" tree
    duplicitous_events: SledEventTreeVec<TimestampedSignedEventMessage>,
    // "rcts" tree
    receipts_nt: SledEventTreeVec<SignedNontransferableReceipt>,
    // "ures" tree
    escrowed_receipts_nt: SledEventTreeVec<SignedNontransferableReceipt>,
    // "vrcs" tree
    receipts_t: SledEventTreeVec<SignedTransferableReceipt>,
    // "vres" tree
    escrowed_receipts_t: SledEventTreeVec<SignedTransferableReceipt>,
    // "pwes" tree
    partially_witnessed_events: SledEventTreeVec<TimestampedSignedEventMessage>,

    #[cfg(feature = "query")]
    accepted_rpy: SledEventTreeVec<SignedReply>,

    #[cfg(feature = "query")]
    escrowed_replys: SledEventTreeVec<SignedReply>,

    #[cfg(feature = "query")]
    mailbox_receipts: SledEventTreeVec<SignedNontransferableReceipt>,
}

// TODO: remove all the `.ok()`s
impl SledEventDatabase {
    pub fn new<'a, P>(path: P) -> Result<Self, DbError>
    where
        P: Into<&'a Path>,
    {
        let mut events_path = PathBuf::new();
        events_path.push(&path.into());
        let mut escrow_path = events_path.clone();

        events_path.push("events");
        escrow_path.push("escrow");

        let db = sled::open(events_path.as_path())?;
        let escrows_db = sled::open(escrow_path.as_path())?;

        Ok(Self {
            identifiers: SledEventTree::new(db.open_tree(b"iids")?),
            receipts_t: SledEventTreeVec::new(db.open_tree(b"vrcs")?),
            receipts_nt: SledEventTreeVec::new(db.open_tree(b"rcts")?),
            key_event_logs: SledEventTreeVec::new(db.open_tree(b"kels")?),
            likely_duplicious_events: SledEventTreeVec::new(db.open_tree(b"ldes")?),
            duplicitous_events: SledEventTreeVec::new(db.open_tree(b"dels")?),
            #[cfg(feature = "query")]
            accepted_rpy: SledEventTreeVec::new(db.open_tree(b"knas")?),
            #[cfg(feature = "query")]
            mailbox_receipts: SledEventTreeVec::new(db.open_tree(b"mbxr")?),

            escrowed_out_of_order: SledEventTreeVec::new(escrows_db.open_tree(b"ooes")?),
            escrowed_partially_signed: SledEventTreeVec::new(escrows_db.open_tree(b"pses")?),
            partially_witnessed_events: SledEventTreeVec::new(escrows_db.open_tree(b"pwes")?),
            escrowed_receipts_nt: SledEventTreeVec::new(escrows_db.open_tree(b"ures")?),
            escrowed_receipts_t: SledEventTreeVec::new(escrows_db.open_tree(b"vres")?),
            #[cfg(feature = "query")]
            escrowed_replys: SledEventTreeVec::new(escrows_db.open_tree(b"knes")?),
        })
    }

    pub fn add_kel_finalized_event(
        &self,
        event: SignedEventMessage,
        id: &IdentifierPrefix,
    ) -> Result<(), DbError> {
        self.key_event_logs
            .push(self.identifiers.designated_key(id)?, event.into())
    }

    pub fn get_kel_finalized_events(
        &self,
        id: &IdentifierPrefix,
    ) -> Option<impl DoubleEndedIterator<Item = TimestampedSignedEventMessage>> {
        self.key_event_logs
            .iter_values(self.identifiers.designated_key(id).ok()?)
    }

    pub fn remove_kel_finalized_event(
        &self,
        id: &IdentifierPrefix,
        event: &SignedEventMessage,
    ) -> Result<(), DbError> {
        self.key_event_logs
            .remove(self.identifiers.designated_key(id)?, &event.into())
    }

    pub fn add_out_of_order_event(
        &self,
        event: SignedEventMessage,
        id: &IdentifierPrefix,
    ) -> Result<(), DbError> {
        self.escrowed_out_of_order
            .push(self.identifiers.designated_key(id)?, event.into())
    }

    pub fn get_out_of_order_events(
        &self,
        id: &IdentifierPrefix,
    ) -> Option<impl DoubleEndedIterator<Item = TimestampedSignedEventMessage>> {
        self.escrowed_out_of_order
            .iter_values(self.identifiers.designated_key(id).ok()?)
    }

    pub fn remove_out_of_order_event(
        &self,
        id: &IdentifierPrefix,
        event: &SignedEventMessage,
    ) -> Result<(), DbError> {
        self.escrowed_out_of_order
            .remove(self.identifiers.designated_key(id)?, &event.into())
    }

    pub fn add_partially_signed_event(
        &self,
        event: SignedEventMessage,
        id: &IdentifierPrefix,
    ) -> Result<(), DbError> {
        self.escrowed_partially_signed
            .push(self.identifiers.designated_key(id)?, event.into())
    }

    pub fn get_all_partially_signed_events(
        &self,
    ) -> Option<impl DoubleEndedIterator<Item = TimestampedSignedEventMessage>> {
        self.escrowed_partially_signed.get_all()
    }

    pub fn get_partially_signed_events(
        &self,
        event: EventMessage<KeyEvent>,
    ) -> Option<impl DoubleEndedIterator<Item = TimestampedSignedEventMessage>> {
        self.escrowed_partially_signed
            .iter_values(
                self.identifiers
                    .designated_key(&event.event.get_prefix())
                    .ok()?,
            )
            .map(|events| {
                events
                    .filter(move |db_event| event.eq(&db_event.signed_event_message.event_message))
            })
    }

    pub fn remove_partially_signed_event(
        &self,
        id: &IdentifierPrefix,
        event: &EventMessage<KeyEvent>,
    ) -> Result<(), DbError> {
        if let Some(partially_signed) = self.get_partially_signed_events(event.clone()) {
            for partially_event in partially_signed {
                self.escrowed_partially_signed
                    .remove(self.identifiers.designated_key(id)?, &partially_event)?;
            }
        }
        Ok(())
    }

    pub fn add_partially_witnessed_event(
        &self,
        event: SignedEventMessage,
        id: &IdentifierPrefix,
    ) -> Result<(), DbError> {
        let event = event.into();
        if !self.partially_witnessed_events.contains_value(&event) {
            self.partially_witnessed_events
                .push(self.identifiers.designated_key(id)?, event)
        } else {
            Ok(())
        }
    }

    pub fn get_partially_witnessed_events(
        &self,
        id: &IdentifierPrefix,
    ) -> Option<impl DoubleEndedIterator<Item = TimestampedSignedEventMessage>> {
        self.partially_witnessed_events
            .iter_values(self.identifiers.designated_key(id).ok()?)
    }

    pub fn remove_partially_witnessed_event(
        &self,
        id: &IdentifierPrefix,
        event: &SignedEventMessage,
    ) -> Result<(), DbError> {
        self.partially_witnessed_events
            .remove(self.identifiers.designated_key(id)?, &event.into())
    }

    pub fn get_all_partially_witnessed(
        &self,
    ) -> Option<impl DoubleEndedIterator<Item = TimestampedSignedEventMessage>> {
        self.partially_witnessed_events.get_all()
    }

    pub fn add_receipt_t(
        &self,
        receipt: SignedTransferableReceipt,
        id: &IdentifierPrefix,
    ) -> Result<(), DbError> {
        self.receipts_t
            .push(self.identifiers.designated_key(id)?, receipt)
    }

    pub fn get_receipts_t(
        &self,
        id: &IdentifierPrefix,
    ) -> Option<impl DoubleEndedIterator<Item = SignedTransferableReceipt>> {
        self.receipts_t
            .iter_values(self.identifiers.designated_key(id).ok()?)
    }

    pub fn add_receipt_nt(
        &self,
        receipt: SignedNontransferableReceipt,
        id: &IdentifierPrefix,
    ) -> Result<(), DbError> {
        self.receipts_nt
            .push(self.identifiers.designated_key(id)?, receipt)
    }

    pub fn get_receipts_nt(
        &self,
        id: &IdentifierPrefix,
    ) -> Option<impl DoubleEndedIterator<Item = SignedNontransferableReceipt>> {
        self.receipts_nt
            .iter_values(self.identifiers.designated_key(id).ok()?)
    }

    pub fn remove_receipts_nt(&self, id: &IdentifierPrefix) -> Result<(), DbError> {
        if let Some(receipts) = self.get_receipts_nt(id) {
            for receipt in receipts {
                self.receipts_nt
                    .remove(self.identifiers.designated_key(id)?, &receipt)?;
            }
        }
        Ok(())
    }

    pub fn add_escrow_t_receipt(
        &self,
        receipt: SignedTransferableReceipt,
        id: &IdentifierPrefix,
    ) -> Result<(), DbError> {
        self.escrowed_receipts_t
            .push(self.identifiers.designated_key(id)?, receipt)
    }

    pub fn get_escrow_t_receipts(
        &self,
        id: &IdentifierPrefix,
    ) -> Option<impl DoubleEndedIterator<Item = SignedTransferableReceipt>> {
        self.escrowed_receipts_t
            .iter_values(self.identifiers.designated_key(id).ok()?)
    }

    pub fn remove_escrow_t_receipt(
        &self,
        id: &IdentifierPrefix,
        receipt: &SignedTransferableReceipt,
    ) -> Result<(), DbError> {
        self.escrowed_receipts_t
            .remove(self.identifiers.designated_key(id)?, receipt)
    }

    pub fn add_escrow_nt_receipt(
        &self,
        receipt: SignedNontransferableReceipt,
        id: &IdentifierPrefix,
    ) -> Result<(), DbError> {
        if !self.escrowed_receipts_nt.contains_value(&receipt) {
            self.escrowed_receipts_nt
                .push(self.identifiers.designated_key(id)?, receipt)
        } else {
            Ok(())
        }
    }

    pub fn get_escrow_nt_receipts(
        &self,
        id: &IdentifierPrefix,
    ) -> Option<impl DoubleEndedIterator<Item = SignedNontransferableReceipt>> {
        self.escrowed_receipts_nt
            .iter_values(self.identifiers.designated_key(id).ok()?)
    }

    pub fn get_all_escrow_nt_receipts(
        &self,
    ) -> Option<impl DoubleEndedIterator<Item = SignedNontransferableReceipt>> {
        self.escrowed_receipts_nt.get_all()
    }

    pub fn remove_escrow_nt_receipt(
        &self,
        id: &IdentifierPrefix,
        receipt: &SignedNontransferableReceipt,
    ) -> Result<(), DbError> {
        self.escrowed_receipts_nt
            .remove(self.identifiers.designated_key(id)?, receipt)
    }

    pub fn add_likely_duplicious_event(
        &self,
        event: EventMessage<KeyEvent>,
        id: &IdentifierPrefix,
    ) -> Result<(), DbError> {
        self.likely_duplicious_events
            .push(self.identifiers.designated_key(id)?, event.into())
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
        }
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
            .remove(self.identifiers.designated_key(id)?, &rpy)
    }

    #[cfg(feature = "query")]
    pub fn add_escrowed_reply(
        &self,
        rpy: SignedReply,
        id: &IdentifierPrefix,
    ) -> Result<(), DbError> {
        self.escrowed_replys
            .push(self.identifiers.designated_key(id)?, rpy)
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
            .remove(self.identifiers.designated_key(id)?, rpy)
    }

    #[cfg(feature = "query")]
    pub fn get_all_escrowed_replys(&self) -> Option<impl DoubleEndedIterator<Item = SignedReply>> {
        self.escrowed_replys.get_all()
    }

    #[cfg(feature = "query")]
    pub fn add_mailbox_receipt(
        &self,
        receipt: SignedNontransferableReceipt,
        id: &IdentifierPrefix,
    ) -> Result<(), DbError> {
        if !self.mailbox_receipts.contains_value(&receipt) {
            self.mailbox_receipts
                .push(self.identifiers.designated_key(id)?, receipt)
        } else {
            Ok(())
        }
    }

    #[cfg(feature = "query")]
    pub fn get_mailbox_receipts(
        &self,
        id: &IdentifierPrefix,
    ) -> Option<impl DoubleEndedIterator<Item = SignedNontransferableReceipt>> {
        self.mailbox_receipts
            .iter_values(self.identifiers.designated_key(id).ok()?)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum DbError {
    #[error("sled error: {0}")]
    Sled(#[from] sled::Error),
    #[error("serde error: {0}")]
    Serde(#[from] serde_cbor::Error),
}
