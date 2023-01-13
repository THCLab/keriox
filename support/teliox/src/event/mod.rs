use crate::error::Error;

use self::{manager_event::ManagerTelEventMessage, vc_event::VCEventMessage};
use keri::prefix::IdentifierPrefix;
use serde::{Deserialize, Serialize};

pub mod manager_event;
pub mod vc_event;
pub mod verifiable_event;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Event {
    Management(ManagerTelEventMessage),
    Vc(VCEventMessage),
}

impl Event {
    pub fn get_prefix(&self) -> IdentifierPrefix {
        match self {
            Event::Management(man) => man.event.content.prefix.clone(),
            Event::Vc(ev) => ev.event.content.data.prefix.clone(),
        }
    }

    pub fn get_sn(&self) -> u64 {
        match self {
            Event::Management(man) => man.event.content.sn,
            Event::Vc(ev) => ev.event.content.data.sn,
        }
    }

    pub fn serialize(&self) -> Result<Vec<u8>, Error> {
        match self {
            Event::Management(man) => Ok(man.serialize()?),
            Event::Vc(ev) => Ok(ev.serialize()?),
        }
    }
}
