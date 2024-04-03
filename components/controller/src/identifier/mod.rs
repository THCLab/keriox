use std::sync::Arc;

#[cfg(test)]
mod test;

use keri_core::{
    event_message::signed_event_message::SignedEventMessage,
    prefix::{BasicPrefix, IdentifierPrefix},
};

use crate::{communication::Communication, error::ControllerError, known_events::KnownEvents};
pub mod kel_managing;

pub struct Identifier {
    id: IdentifierPrefix,
    known_events: Arc<KnownEvents>,
    communication: Arc<Communication>,
    pub to_notify: Vec<SignedEventMessage>,
}

impl Identifier {
    pub fn new(
        id: IdentifierPrefix,
        known_events: Arc<KnownEvents>,
        communication: Arc<Communication>,
    ) -> Self {
        Self {
            id,
            known_events,
            communication,
            to_notify: vec![],
        }
    }

    pub fn current_public_keys(&self) -> Result<Vec<BasicPrefix>, ControllerError> {
        self.known_events.current_public_keys(&self.id)
    }
}
