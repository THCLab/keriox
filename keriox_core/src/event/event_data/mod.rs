pub mod delegated;
pub mod inception;
pub mod interaction;
pub mod rotation;

use crate::{
    error::Error,
    event_message::{EventTypeTag, Typeable},
    state::{EventSemantics, IdentifierState},
};
use serde::{Deserialize, Serialize};

pub use self::{
    delegated::DelegatedInceptionEvent, inception::InceptionEvent, interaction::InteractionEvent,
    rotation::RotationEvent,
};

/// Event Data
///
/// Event Data conveys the semantic content of a KERI event.
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
#[serde(untagged, rename_all = "lowercase")]
#[rkyv(derive(Debug))]
pub enum EventData {
    Dip(DelegatedInceptionEvent),
    Icp(InceptionEvent),
    Rot(RotationEvent),
    Ixn(InteractionEvent),
    Drt(RotationEvent),
}

impl EventSemantics for EventData {
    fn apply_to(&self, state: IdentifierState) -> Result<IdentifierState, Error> {
        match self {
            Self::Icp(e) => e.apply_to(state),
            Self::Rot(e) => e.apply_to(state),
            Self::Ixn(e) => e.apply_to(state),
            Self::Dip(e) => e.apply_to(state),
            Self::Drt(e) => e.apply_to(state),
        }
    }
}

impl From<EventData> for EventTypeTag {
    fn from(ed: EventData) -> Self {
        match ed {
            EventData::Icp(_) => EventTypeTag::Icp,
            EventData::Rot(_) => EventTypeTag::Rot,
            EventData::Ixn(_) => EventTypeTag::Ixn,
            EventData::Dip(_) => EventTypeTag::Dip,
            EventData::Drt(_) => EventTypeTag::Drt,
        }
    }
}

impl Typeable for EventData {
    type TypeTag = EventTypeTag;
    fn get_type(&self) -> EventTypeTag {
        self.into()
    }
}
