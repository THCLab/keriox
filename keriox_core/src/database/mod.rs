use timestamped::TimestampedSignedEventMessage;

use crate::{
    event_message::{
        signature::{Nontransferable, Transferable},
        signed_event_message::{
            SignedEventMessage, SignedNontransferableReceipt, SignedTransferableReceipt,
        },
    },
    prefix::IdentifierPrefix,
};

pub mod escrow;
#[cfg(feature = "mailbox")]
pub mod mailbox;
pub mod redb;
pub mod sled;
pub(crate) mod tables;
pub(crate) mod timestamped;

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
    ) -> Option<impl DoubleEndedIterator<Item = Nontransferable>>;
}
