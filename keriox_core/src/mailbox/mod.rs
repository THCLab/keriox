use serde::{Deserialize, Serialize};

use crate::event_message::signed_event_message::{
    SignedEventMessage, SignedNontransferableReceipt,
};

pub mod exchange;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct MailboxResponse {
    pub receipt: Vec<SignedNontransferableReceipt>,
    pub multisig: Vec<SignedEventMessage>,
    pub delegate: Vec<SignedEventMessage>,
}
