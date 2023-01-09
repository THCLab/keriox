use serde::{Serialize, Deserialize};

use crate::event_message::signed_event_message::{SignedNontransferableReceipt, SignedEventMessage};

pub mod exchange;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct MailboxResponse {
    pub receipt: Vec<SignedNontransferableReceipt>,
    pub multisig: Vec<SignedEventMessage>,
    pub delegate: Vec<SignedEventMessage>,
}