use base64::URL_SAFE;
use keri::prefix::CesrPrimitive;
use sai::SelfAddressingPrefix;
use serde::{Deserialize, Serialize};

use crate::error::Error;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EventSourceSeal {
    pub sn: u64,
    pub digest: SelfAddressingPrefix,
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
    pub fn new(sn: u64, dig: SelfAddressingPrefix) -> Self {
        let seal = EventSourceSeal { sn, digest: dig };
        Self { seal }
    }

    pub fn serialize(&self) -> Result<Vec<u8>, Error> {
        Ok([
            "GAB".as_bytes().to_vec(),
            "0A".as_bytes().to_vec(),
            num_to_base_64(self.seal.sn)?.as_bytes().to_vec(),
            self.seal.digest.to_str().as_bytes().to_vec(),
        ]
        .concat())
    }
}

fn num_to_base_64(sn: u64) -> Result<String, Error> {
    let mut tmp = vec![0, 0, 0, 0, 0, 0, 0, 0];
    tmp.extend(u64::to_be_bytes(sn).to_vec());
    Ok((base64::encode_config(tmp, URL_SAFE)[..22]).to_string())
}
