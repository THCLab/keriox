pub mod delegated;
pub mod inception;
pub mod interaction;
pub mod rotation;

use crate::{
    error::Error,
    event_message::{EventTypeTag, Typeable},
    state::{EventSemantics, IdentifierState},
};
use serde::{de, Deserialize, Deserializer, Serialize};
use serde_json::Value;

pub use self::{
    delegated::DelegatedInceptionEvent, inception::InceptionEvent, interaction::InteractionEvent,
    rotation::RotationEvent,
};

/// Event Data
///
/// Event Data conveys the semantic content of a KERI event.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(untagged, rename_all = "lowercase")]
pub enum EventData {
    Icp(InceptionEvent),
    Rot(RotationEvent),
    Ixn(InteractionEvent),
    Dip(DelegatedInceptionEvent),
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
