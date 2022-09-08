use crate::{event::EventMessage, event_message::key_event_message::KeyEvent, prefix::{IdentifierPrefix, BasicPrefix}};

use super::error::ControllerError;

pub enum ActionRequired {
	MultisigRequest(EventMessage<KeyEvent>),
	DelegationRequest(EventMessage<KeyEvent>),
}

pub fn pull_mailbox(about_id: &IdentifierPrefix, source_id: BasicPrefix) -> Result<Vec<ActionRequired>, ControllerError> {
	todo!()
}