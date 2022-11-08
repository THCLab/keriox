use std::str::FromStr;

use crate::event_parsing::error::Error;

use super::DerivationCode;

#[derive(Debug, PartialEq, Clone, Copy, Hash, Eq)]
pub enum SelfSigning {
    Ed25519Sha512,
    ECDSAsecp256k1Sha256,
    Ed448,
}

impl DerivationCode for SelfSigning {
    fn value_size(&self) -> usize {
        match self {
            Self::Ed25519Sha512 | Self::ECDSAsecp256k1Sha256 => 86,
            Self::Ed448 => 152,
        }
    }

    fn soft_size(&self) -> usize {
        0
    }

    fn hard_size(&self) -> usize {
        match self {
            Self::Ed25519Sha512 | Self::ECDSAsecp256k1Sha256 => 2,
            Self::Ed448 => 4,
        }
    }

    fn to_str(&self) -> String {
        match self {
            Self::Ed25519Sha512 => "0B",
            Self::ECDSAsecp256k1Sha256 => "0C",
            Self::Ed448 => "1AAE",
        }
        .into()
    }
}

impl FromStr for SelfSigning {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.get(..1).ok_or_else(|| Error::EmptyCodeError)? {
            "0" => match &s[1..2] {
                "B" => Ok(Self::Ed25519Sha512),
                "C" => Ok(Self::ECDSAsecp256k1Sha256),
                _ => Err(Error::UnknownCodeError),
            },
            "1" => match &s[1..4] {
                "AAE" => Ok(Self::Ed448),
                _ => Err(Error::UnknownCodeError),
            },
            _ => Err(Error::UnknownCodeError),
        }
    }
}
