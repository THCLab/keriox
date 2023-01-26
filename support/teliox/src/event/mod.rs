use crate::error::Error;
use version::Versional;

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
            Event::Management(man) => man.data.prefix.clone(),
            Event::Vc(ev) => ev.data.data.prefix.clone(),
        }
    }

    pub fn get_sn(&self) -> u64 {
        match self {
            Event::Management(man) => man.data.sn,
            Event::Vc(ev) => ev.data.data.sn,
        }
    }

    pub fn serialize(&self) -> Result<Vec<u8>, Error> {
        match self {
            Event::Management(man) => Ok(Versional::serialize(man)?),
            Event::Vc(ev) => Ok(Versional::serialize(ev)?),
        }
    }
}
