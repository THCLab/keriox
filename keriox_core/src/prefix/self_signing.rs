use core::{fmt, str::FromStr};

use cesrox::{
    conversion::from_text_to_bytes,
    derivation_code::DerivationCode,
    primitives::codes::{self_signing::SelfSigning, PrimitiveCode},
};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use super::{error::Error, CesrPrimitive};

/// Self Signing Derivations
///
/// A self signing prefix derivation outputs a signature as its derivative (2.3.5)
#[derive(PartialEq, Clone, Hash, Eq)]
pub enum SelfSigningPrefix {
    Ed25519Sha512(Vec<u8>),
    ECDSAsecp256k1Sha256(Vec<u8>),
    Ed448(Vec<u8>),
}

impl fmt::Debug for SelfSigningPrefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.to_str())
    }
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
                code,
                from_text_to_bytes(s[code.code_size()..].as_bytes())?[code.code_size()..].to_vec(),
            ))
        } else {
            Err(Error::IncorrectLengthError(s.into()))
        }
    }
}

impl CesrPrimitive for SelfSigningPrefix {
    fn derivative(&self) -> Vec<u8> {
        match self {
            SelfSigningPrefix::Ed25519Sha512(signature)
            | SelfSigningPrefix::ECDSAsecp256k1Sha256(signature)
            | SelfSigningPrefix::Ed448(signature) => signature.clone(),
        }
    }
    fn derivation_code(&self) -> PrimitiveCode {
        PrimitiveCode::SelfSigning(self.get_code())
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
