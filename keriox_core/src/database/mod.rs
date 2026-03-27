use std::sync::Arc;

use timestamped::TimestampedSignedEventMessage;

#[cfg(feature = "query")]
use crate::query::reply_event::SignedReply;
use crate::{
    event::KeyEvent,
    event_message::{
        msg::KeriEvent,
        signature::{Nontransferable, Transferable},
        signed_event_message::{
            SignedEventMessage, SignedNontransferableReceipt, SignedTransferableReceipt,
        },
    },
    prefix::{IdentifierPrefix, IndexedSignature},
    state::IdentifierState,
};

#[cfg(feature = "mailbox")]
pub mod mailbox;
pub mod memory;
#[cfg(feature = "storage-redb")]
pub mod redb;
pub(crate) mod rkyv_adapter;
pub mod timestamped;

pub enum QueryParameters<'a> {
    BySn {
        id: IdentifierPrefix,
        sn: u64,
    },
    Range {
        id: IdentifierPrefix,
        start: u64,
        limit: u64,
    },
    All {
        id: &'a IdentifierPrefix,
    },
}

pub trait EventDatabase {
    type Error;
    type LogDatabaseType: LogDatabase<'static>;

    fn get_log_db(&self) -> Arc<Self::LogDatabaseType>;

    fn add_kel_finalized_event(
        &self,
        event: SignedEventMessage,
        id: &IdentifierPrefix,
    ) -> Result<(), Self::Error>;

    fn add_receipt_t(
        &self,
        receipt: SignedTransferableReceipt,
        id: &IdentifierPrefix,
    ) -> Result<(), Self::Error>;

    fn add_receipt_nt(
        &self,
        receipt: SignedNontransferableReceipt,
        id: &IdentifierPrefix,
    ) -> Result<(), Self::Error>;

    fn get_key_state(&self, id: &IdentifierPrefix) -> Option<IdentifierState>;

    fn get_kel_finalized_events(
        &self,
        params: QueryParameters,
    ) -> Option<impl DoubleEndedIterator<Item = TimestampedSignedEventMessage>>;

    fn get_receipts_t(
        &self,
        params: QueryParameters,
    ) -> Option<impl DoubleEndedIterator<Item = Transferable>>;

    fn get_receipts_nt(
        &self,
        params: QueryParameters,
    ) -> Option<impl DoubleEndedIterator<Item = SignedNontransferableReceipt>>;

    fn accept_to_kel(&self, event: &KeriEvent<KeyEvent>) -> Result<(), Self::Error>;

    #[cfg(feature = "query")]
    fn save_reply(&self, reply: SignedReply) -> Result<(), Self::Error>;
    #[cfg(feature = "query")]
    fn get_reply(&self, id: &IdentifierPrefix, from_who: &IdentifierPrefix) -> Option<SignedReply>;
}

pub trait LogDatabase<'db>: Send + Sync {
    type DatabaseType;
    type Error;
    type TransactionType;

    fn new(db: Arc<Self::DatabaseType>) -> Result<Self, Self::Error>
    where
        Self: Sized;

    fn log_event(
        &self,
        txn: &Self::TransactionType,
        signed_event: &SignedEventMessage,
    ) -> Result<(), Self::Error>;

    fn log_event_with_new_transaction(
        &self,
        signed_event: &SignedEventMessage,
    ) -> Result<(), Self::Error>;

    fn log_receipt(
        &self,
        txn: &Self::TransactionType,
        signed_receipt: &SignedNontransferableReceipt,
    ) -> Result<(), Self::Error>;

    fn log_receipt_with_new_transaction(
        &self,
        signed_receipt: &SignedNontransferableReceipt,
    ) -> Result<(), Self::Error>;

    fn get_signed_event(
        &self,
        said: &said::SelfAddressingIdentifier,
    ) -> Result<Option<TimestampedSignedEventMessage>, Self::Error>;

    fn get_event(
        &self,
        said: &said::SelfAddressingIdentifier,
    ) -> Result<Option<KeriEvent<KeyEvent>>, Self::Error>;

    fn get_signatures(
        &self,
        said: &said::SelfAddressingIdentifier,
    ) -> Result<Option<impl Iterator<Item = IndexedSignature>>, Self::Error>;

    fn get_nontrans_couplets(
        &self,
        said: &said::SelfAddressingIdentifier,
    ) -> Result<Option<impl Iterator<Item = Nontransferable>>, Self::Error>;

    fn get_trans_receipts(
        &self,
        said: &said::SelfAddressingIdentifier,
    ) -> Result<impl DoubleEndedIterator<Item = Transferable>, Self::Error>;

    fn remove_nontrans_receipt(
        &self,
        txn_mode: &Self::TransactionType,
        said: &said::SelfAddressingIdentifier,
        nontrans: impl IntoIterator<Item = Nontransferable>,
    ) -> Result<(), Self::Error>;

    fn remove_nontrans_receipt_with_new_transaction(
        &self,
        said: &said::SelfAddressingIdentifier,
        nontrans: impl IntoIterator<Item = Nontransferable>,
    ) -> Result<(), Self::Error>;
}

pub trait SequencedEventDatabase: Send + Sync {
    type DatabaseType;
    type Error;
    type DigestIter: Iterator<Item = said::SelfAddressingIdentifier>;

    fn new(db: Arc<Self::DatabaseType>, table_name: &'static str) -> Result<Self, Self::Error>
    where
        Self: Sized;

    fn insert(
        &self,
        identifier: &IdentifierPrefix,
        sn: u64,
        digest: &said::SelfAddressingIdentifier,
    ) -> Result<(), Self::Error>;

    fn get(&self, identifier: &IdentifierPrefix, sn: u64) -> Result<Self::DigestIter, Self::Error>;

    fn get_greater_than(
        &self,
        identifier: &IdentifierPrefix,
        sn: u64,
    ) -> Result<Self::DigestIter, Self::Error>;

    fn remove(
        &self,
        identifier: &IdentifierPrefix,
        sn: u64,
        said: &said::SelfAddressingIdentifier,
    ) -> Result<(), Self::Error>;
}

pub trait EscrowCreator {
    type EscrowDatabaseType: EscrowDatabase;
    fn create_escrow_db(&self, table_name: &'static str) -> Self::EscrowDatabaseType;
}

pub trait EscrowDatabase: Send + Sync {
    type EscrowDatabaseType;
    type LogDatabaseType;
    type Error;
    type EventIter: Iterator<Item = SignedEventMessage>;

    fn new(
        escrow: Arc<
            dyn SequencedEventDatabase<
                DatabaseType = Self::EscrowDatabaseType,
                Error = Self::Error,
                DigestIter = Box<dyn Iterator<Item = said::SelfAddressingIdentifier>>,
            >,
        >,
        log: Arc<Self::LogDatabaseType>,
    ) -> Self
    where
        Self: Sized;

    fn save_digest(
        &self,
        id: &IdentifierPrefix,
        sn: u64,
        event_digest: &said::SelfAddressingIdentifier,
    ) -> Result<(), Self::Error>;

    fn insert(&self, event: &SignedEventMessage) -> Result<(), Self::Error>;

    fn insert_key_value(
        &self,
        id: &IdentifierPrefix,
        sn: u64,
        event: &SignedEventMessage,
    ) -> Result<(), Self::Error>;

    fn get(&self, identifier: &IdentifierPrefix, sn: u64) -> Result<Self::EventIter, Self::Error>;

    fn get_from_sn(
        &self,
        identifier: &IdentifierPrefix,
        sn: u64,
    ) -> Result<Self::EventIter, Self::Error>;

    fn remove(&self, event: &KeriEvent<KeyEvent>);

    fn contains(
        &self,
        id: &IdentifierPrefix,
        sn: u64,
        digest: &said::SelfAddressingIdentifier,
    ) -> Result<bool, Self::Error>;
}
