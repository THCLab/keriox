use super::super::sections::seal::*;
use crate::error::Error;
use crate::state::{EventSemantics, IdentifierState};
use said::SelfAddressingIdentifier;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct InteractionEvent {
    #[serde(rename = "p")]
    pub previous_event_hash: SelfAddressingIdentifier,

    #[serde(rename = "a")]
    pub data: Vec<Seal>,
}

impl InteractionEvent {
    pub fn new(previous_event_hash: SelfAddressingIdentifier, data: Vec<Seal>) -> Self {
        InteractionEvent {
            previous_event_hash,
            data,
        }
    }
}

impl EventSemantics for InteractionEvent {
    fn apply_to(&self, state: IdentifierState) -> Result<IdentifierState, Error> {
        Ok(IdentifierState { ..state })
    }
}
