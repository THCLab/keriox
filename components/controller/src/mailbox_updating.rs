// use super::{error::ControllerError, identifier_controller::IdentifierController};
use futures::{StreamExt, TryStreamExt};
use keri_core::{
    actor::{event_generator, prelude::Message},
    event::{
        event_data::EventData,
        sections::seal::{EventSeal, Seal},
        KeyEvent,
    },
    event_message::{
        msg::KeriEvent,
        signed_event_message::{Notice, SignedEventMessage, SignedNontransferableReceipt},
    },
    mailbox::{
        exchange::{ExchangeMessage, ForwardTopic},
        MailboxResponse,
    },
    prefix::IdentifierPrefix, query::mailbox::QueryTopics,
};

use crate::{error::ControllerError, identifier::Identifier};

#[derive(Default, Debug, Clone)]
/// Struct for tracking what was the last indexes of processed mailbox messages.
/// Events in mailbox aren't removed after getting them, so it prevents
/// processing the same event multiple times.
pub struct MailboxReminder {
    pub receipt: usize,
    pub multisig: usize,
    pub delegate: usize,
}

impl MailboxReminder {
    pub fn to_query_topics(&self) -> QueryTopics {
		QueryTopics {
            credential: 0,
            receipt: self.receipt,
            replay: 0,
            multisig: self.multisig,
            delegate: self.delegate,
            reply: 0,
        }
	}
}

#[derive(Debug)]
pub enum ActionRequired {
    MultisigRequest(KeriEvent<KeyEvent>, ExchangeMessage),
    // Contains delegating event and exchange message that will be send to
    // delegate after delegating event confirmation.
    DelegationRequest(KeriEvent<KeyEvent>, ExchangeMessage),
}
