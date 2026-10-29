// use super::{error::ControllerError, identifier_controller::IdentifierController};
use keri_core::{
    event::KeyEvent, event_message::msg::KeriEvent, mailbox::exchange::ExchangeMessage,
};

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub enum ActionRequired {
    MultisigRequest(KeriEvent<KeyEvent>, ExchangeMessage),
    /// Contains delegating event and exchange message that will be send to
    /// delegate after delegating event confirmation.
    DelegationRequest(KeriEvent<KeyEvent>, ExchangeMessage),
}
