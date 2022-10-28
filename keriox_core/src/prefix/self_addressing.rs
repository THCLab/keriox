use super::Prefix;
use crate::derivation::{self_addressing::SelfAddressing, DerivationCode};
use crate::event_parsing::parsing::from_text_to_bytes;
use core::{fmt, str::FromStr};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use super::error::Error;

#[derive(Debug, PartialEq, Clone, Hash, Eq)]
pub struct SelfAddressingPrefix {
    pub derivation: SelfAddressing,
    pub digest: Vec<u8>,
}

impl SelfAddressingPrefix {
    pub fn new(code: SelfAddressing, digest: Vec<u8>) -> Self {
        Self {
            derivation: code,
            digest,
        }
    }

    pub fn verify_binding(&self, sed: &[u8]) -> bool {
        self.derivation.digest(sed) == self.digest
    }
}

impl FromStr for SelfAddressingPrefix {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let code = SelfAddressing::from_str(s)?;
        let c_len = code.code_len();
        if s.len() == code.prefix_b64_len() {
            let decoded = from_text_to_bytes(&s[c_len..].as_bytes())?[c_len..].to_vec();

            Ok(Self::new(code, decoded))
        } else {
            Err(Error::IncorrectLengthError(s.into()))
        }
    }
}

impl Prefix for SelfAddressingPrefix {
    fn derivative(&self) -> Vec<u8> {
        self.digest.to_owned()
    }
    fn derivation_code(&self) -> String {
        self.derivation.to_str()
    }
}

impl fmt::Display for SelfAddressingPrefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_str())
    }
}

/// Serde compatible Serialize
impl Serialize for SelfAddressingPrefix {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_str())
    }
}

/// Serde compatible Deserialize
impl<'de> Deserialize<'de> for SelfAddressingPrefix {
    fn deserialize<D>(deserializer: D) -> Result<SelfAddressingPrefix, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;

        SelfAddressingPrefix::from_str(&s).map_err(serde::de::Error::custom)
    }
}

impl Default for SelfAddressingPrefix {
    fn default() -> Self {
        Self {
            derivation: SelfAddressing::Blake3_256,
            digest: vec![],
        }
    }
}
