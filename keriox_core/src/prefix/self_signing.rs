use super::error::Error;
use super::Prefix;
use crate::event_parsing::{
    codes::{self_signing::SelfSigning, DerivationCode},
    parsing::from_text_to_bytes,
};
use core::str::FromStr;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Self Signing Derivations
///
/// A self signing prefix derivation outputs a signature as its derivative (2.3.5)
#[derive(Debug, PartialEq, Clone, Hash, Eq)]
pub enum SelfSigningPrefix {
    Ed25519Sha512(Vec<u8>),
    ECDSAsecp256k1Sha256(Vec<u8>),
    Ed448(Vec<u8>),
}

impl SelfSigningPrefix {
    pub fn new(code: SelfSigning, signature: Vec<u8>) -> Self {
        match code {
            SelfSigning::Ed25519Sha512 => Self::Ed25519Sha512(signature),
            SelfSigning::ECDSAsecp256k1Sha256 => Self::ECDSAsecp256k1Sha256(signature),
            SelfSigning::Ed448 => Self::Ed448(signature),
        }
    }

    pub fn get_code(&self) -> SelfSigning {
        match self {
            SelfSigningPrefix::Ed25519Sha512(_) => SelfSigning::Ed25519Sha512,
            SelfSigningPrefix::ECDSAsecp256k1Sha256(_) => SelfSigning::ECDSAsecp256k1Sha256,
            SelfSigningPrefix::Ed448(_) => SelfSigning::Ed448,
        }
    }
}

impl FromStr for SelfSigningPrefix {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let code = SelfSigning::from_str(s)?;

        if s.len() == code.full_size() {
            Ok(Self::new(
                code.into(),
                from_text_to_bytes(&s[code.code_size()..].as_bytes())?[code.code_size()..].to_vec(),
            ))
        } else {
            Err(Error::IncorrectLengthError(s.into()))
        }
    }
}

impl Prefix for SelfSigningPrefix {
    fn derivative(&self) -> Vec<u8> {
        match self {
            SelfSigningPrefix::Ed25519Sha512(signature)
            | SelfSigningPrefix::ECDSAsecp256k1Sha256(signature)
            | SelfSigningPrefix::Ed448(signature) => signature.clone(),
        }
    }
    fn derivation_code(&self) -> String {
        self.get_code().to_str()
    }
}

/// Serde compatible Serialize
impl Serialize for SelfSigningPrefix {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_str())
    }
}

/// Serde compatible Deserialize
impl<'de> Deserialize<'de> for SelfSigningPrefix {
    fn deserialize<D>(deserializer: D) -> Result<SelfSigningPrefix, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;

        SelfSigningPrefix::from_str(&s).map_err(serde::de::Error::custom)
    }
}
