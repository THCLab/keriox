use crate::error::Error;
use crate::seal::AttachedSourceSeal;
use serde::{Deserialize, Serialize};
use version::Versional;

use super::Event;

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct VerifiableEvent {
    pub event: Event,
    pub seal: AttachedSourceSeal,
}

impl VerifiableEvent {
    pub fn new(event: Event, seal: AttachedSourceSeal) -> Self {
        Self { event, seal }
    }

    pub fn serialize(&self) -> Result<Vec<u8>, Error> {
        Ok(match &self.event {
            Event::Management(man) => {
                [Versional::serialize(man)?, self.seal.serialize()?].join("-".as_bytes())
            }
            Event::Vc(vc) => {
                [Versional::serialize(vc)?, self.seal.serialize()?].join("-".as_bytes())
            }
        })
    }

    pub fn get_event(&self) -> Event {
        self.event.clone()
    }
}
