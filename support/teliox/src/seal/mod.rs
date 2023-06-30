use said::SelfAddressingIdentifier;
use serde::{Deserialize, Serialize};

use crate::error::Error;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EventSourceSeal {
    pub sn: u64,
    pub digest: SelfAddressingIdentifier,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AttachedSourceSeal {
    pub seal: EventSourceSeal,
}

impl From<EventSourceSeal> for AttachedSourceSeal {
    fn from(seal: EventSourceSeal) -> Self {
        AttachedSourceSeal { seal }
    }
}

impl AttachedSourceSeal {
    pub fn new(sn: u64, dig: SelfAddressingIdentifier) -> Self {
        let seal = EventSourceSeal { sn, digest: dig };
        Self { seal }
    }

    pub fn serialize(&self) -> Result<Vec<u8>, Error> {
        let attachment = cesrox::group::Group::SourceSealCouples(vec![(
            self.seal.sn,
            self.seal.digest.clone().into(),
        )]);
        Ok(attachment.to_cesr_str().as_bytes().to_vec())
    }
}
