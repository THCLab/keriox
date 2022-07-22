use base64::URL_SAFE;
use serde::Deserialize;

use super::payload_size::PayloadType;
use crate::error::Error;

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct MaterialPath {
    lead_bytes: usize,
    // base64 reprezentation of path string
    base: String,
}

impl MaterialPath {
    pub fn new(pt: PayloadType, path: String) -> Self {
        // fill input string with A
        let b64path = match path.len() % 4 {
            0 => path,
            n => ["A".repeat(4 - n), path].join(""),
        };
        let leading_bytes = match pt {
            PayloadType::A4 => 0,
            PayloadType::A5 => 1,
            PayloadType::A6 => 2,
            _ => todo!(),
        };

        Self {
            base: b64path,
            lead_bytes: leading_bytes,
        }
    }

    pub fn to_cesr(&self) -> String {
        let ts = self.base.clone().len() % 4;
        // how many chars are missing for base64 encoding
        let ws = (4 - ts) % 4;

        // post conv lead size in bytes
        // decide what starting code should be used
        let ls = (3 - ts) % 3;
        let base = ["A".repeat(ws), self.base.clone()].join("");
        let decoded_base = base64::decode_config(&base, URL_SAFE).unwrap();
        let code = match ls {
            0 => PayloadType::A4,
            1 => PayloadType::A5,
            2 => PayloadType::A6,
            _ => {
                todo!()
            }
        };
        let size = decoded_base.len() / 3;
        [code.adjust_with_num(size as u16), base].join("")
    }

    pub fn to_raw(&self) -> Result<Vec<u8>, Error> {
        let decoded_base = base64::decode_config(&self.base, URL_SAFE)?;
        let raw = &decoded_base[self.lead_bytes..];
        Ok(raw.to_vec())
    }
}

#[test]
pub fn test_path_to_cesr() -> Result<(), Error> {
    assert_eq!(
        MaterialPath::new(PayloadType::A6, "-".into()).to_cesr(),
        "6AABAAA-"
    );
    assert_eq!(
        MaterialPath::new(PayloadType::A5, "-A".into()).to_cesr(),
        "5AABAA-A"
    );
    assert_eq!(
        MaterialPath::new(PayloadType::A4, "-A-".into()).to_cesr(),
        "4AABA-A-"
    );
    assert_eq!(
        MaterialPath::new(PayloadType::A4, "-A-B".into()).to_cesr(),
        "4AAB-A-B"
    );

    Ok(())
}
