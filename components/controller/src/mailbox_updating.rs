// use super::{error::ControllerError, identifier_controller::IdentifierController};
use keri_core::{
    event::KeyEvent, event_message::msg::KeriEvent, mailbox::exchange::ExchangeMessage,
    query::mailbox::QueryTopics,
};

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
