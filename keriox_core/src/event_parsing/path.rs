use base64::URL_SAFE;
use serde::Deserialize;

use super::codes::{material_path_codes::MaterialPathCode, DerivationCode};
use super::error::Error;

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct MaterialPath {
    lead_bytes: usize,
    // base64 representation of path string
    base: String,
}

impl MaterialPath {
    pub fn new(pt: MaterialPathCode, path: String) -> Self {
        let lead_bytes = pt.lead_bytes_len();
        MaterialPath {
            lead_bytes,
            base: path,
        }
    }

    pub fn to_path(path: String) -> Self {
        let len_modulo = path.len() % 4;
        let leading_bytes = (3 - (len_modulo % 3)) % 3;

        // fill input string with A
        let b64path = match len_modulo {
            0 => path,
            n => ["A".repeat(4 - n), path].join(""),
        };

        Self {
            base: b64path,
            lead_bytes: leading_bytes,
        }
    }

    pub fn to_cesr(&self) -> String {
        let decoded_base = base64::decode_config(&self.base, URL_SAFE).unwrap();

        let size = decoded_base.len() / 3;
        let code = MaterialPathCode::new(self.lead_bytes, size as u16).unwrap();
        [code.to_str(), self.base.clone()].join("")
    }

    pub fn to_raw(&self) -> Result<Vec<u8>, Error> {
        let decoded_base = base64::decode_config(&self.base, URL_SAFE)?;
        let raw = &decoded_base[self.lead_bytes..];
        Ok(raw.to_vec())
    }
}

#[test]
pub fn test_path_to_cesr() -> Result<(), Error> {
    assert_eq!(MaterialPath::to_path("-".into()).to_cesr(), "6AABAAA-");
    assert_eq!(MaterialPath::to_path("-A".into()).to_cesr(), "5AABAA-A");
    assert_eq!(MaterialPath::to_path("-A-".into()).to_cesr(), "4AABA-A-");
    assert_eq!(MaterialPath::to_path("-A-B".into()).to_cesr(), "4AAB-A-B");
    assert_eq!(
        MaterialPath::to_path("-a-b-c".into()).to_cesr(),
        "5AACAA-a-b-c"
    );

    assert_eq!(
        MaterialPath::to_path("-field0".into()).to_cesr(),
        "4AACA-field0"
    );

    assert_eq!(
        MaterialPath::to_path("-field0-field1-field3".into()).to_cesr(),
        "6AAGAAA-field0-field1-field3"
    );

    Ok(())
}
