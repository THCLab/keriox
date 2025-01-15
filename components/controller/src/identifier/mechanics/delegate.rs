use keri_core::actor::prelude::HashFunctionCode;
use keri_core::{
    actor::prelude::SerializationFormats,
    event::{
        sections::seal::{EventSeal, Seal},
        KeyEvent,
    },
    event_message::msg::KeriEvent,
    mailbox::exchange::{Exchange, ExchangeMessage, ForwardTopic, FwdArgs},
};

use crate::identifier::Identifier;

use super::MechanicsError;

impl Identifier {
    /// Generates delegating event (ixn) and exchange event that contains
    /// delegated event which will be send to delegate after ixn finalization.
    pub fn delegate(
        &self,
        delegated_event: &KeriEvent<KeyEvent>,
    ) -> Result<(KeriEvent<KeyEvent>, ExchangeMessage), MechanicsError> {
        let delegate = delegated_event.data.get_prefix();
        let delegated_seal = {
            let event_digest = delegated_event.digest()?;
            let sn = delegated_event.data.get_sn();
            Seal::Event(EventSeal::new(delegate.clone(), sn, event_digest))
        };
        let delegating_event = self
            .known_events
            .anchor_with_seal(&self.id, &[delegated_seal])?;
        let exn_message = Exchange::Fwd {
            args: FwdArgs {
                recipient_id: delegate,
                topic: ForwardTopic::Delegate,
            },
            to_forward: delegating_event.clone(),
        }
        .to_message(SerializationFormats::JSON, HashFunctionCode::Blake3_256);
        Ok((delegating_event, exn_message))
    }
}
