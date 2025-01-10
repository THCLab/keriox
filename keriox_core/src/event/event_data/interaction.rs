use super::super::sections::seal::*;
use crate::database::redb::rkyv_adapter::said_wrapper::SaidValue;
use crate::error::Error;
use crate::state::{EventSemantics, IdentifierState};
use said::SelfAddressingIdentifier;
use serde::{Deserialize, Serialize};

#[derive(
    Serialize,
    Deserialize,
    Debug,
    Clone,
    PartialEq,
    rkyv::Archive,
    rkyv::Serialize,
    rkyv::Deserialize,
)]
#[rkyv(derive(Debug))]
pub struct InteractionEvent {
    #[serde(rename = "p")]
    pub previous_event_hash: SaidValue,

    #[serde(rename = "a")]
    pub data: Vec<Seal>,
}

impl InteractionEvent {
    pub fn new(previous_event_hash: SelfAddressingIdentifier, data: Vec<Seal>) -> Self {
        InteractionEvent {
            previous_event_hash: previous_event_hash.into(),
            data,
        }
    }
}

impl EventSemantics for InteractionEvent {
    fn apply_to(&self, state: IdentifierState) -> Result<IdentifierState, Error> {
        Ok(IdentifierState { ..state })
    }
}
