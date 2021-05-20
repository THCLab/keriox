use super::super::sections::seal::EventSeal;
use crate::prefix::SelfAddressingPrefix;
use crate::state::EventSemantics;
use serde::{Deserialize, Serialize};

/// Non-Transferrable Receipt
///
/// A receipt created by an Identifier of a non-transferrable type.
/// Mostly intended for use by Witnesses.
/// NOTE: This receipt has a unique structure to it's appended
/// signatures
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Receipt {
    /// Receipted Event Digest
    ///
    /// A Qualified Digest of the event which this receipt is made for.
    #[serde(rename = "d")]
    pub receipted_event_digest: SelfAddressingPrefix,
}

impl EventSemantics for Receipt {}

// /// Transferrable Receipt
// ///
// /// Event Receipt which is suitable for creation by Transferable
// /// Identifiers. Provides both the signatures and a commitment to
// /// the latest establishment event of the receipt creator.
// /// Mostly intended for use by Validators
// #[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
// pub struct ReceiptTransferable {
//     /// Receipted Event Digest
//     ///
//     /// A Qualified Digest of the event which this receipt is made for.
//     #[serde(rename = "d")]
//     pub receipted_event_digest: SelfAddressingPrefix,

//     /// Validator Seal
//     ///
//     /// An Event Seal which indicates the latest establishment event of
//     /// the Validator when the Receipt was made
//     #[serde(rename = "a")]
//     pub validator_seal: EventSeal,
// }

// impl EventSemantics for ReceiptTransferable {}
