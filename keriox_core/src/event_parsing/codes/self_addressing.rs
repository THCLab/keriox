use std::str::FromStr;

use crate::event_parsing::{codes::DerivationCode, error::Error};

#[derive(Debug, PartialEq, Clone, Hash, Eq)]
pub enum SelfAddressing {
    Blake3_256,
    Blake2B256(Vec<u8>),
    Blake2S256(Vec<u8>),
    SHA3_256,
    SHA2_256,
    Blake3_512,
    SHA3_512,
    Blake2B512,
    SHA2_512,
}

impl DerivationCode for SelfAddressing {
    fn value_size(&self) -> usize {
        match self {
            Self::Blake3_256
            | Self::Blake2B256(_)
            | Self::Blake2S256(_)
            | Self::SHA3_256
            | Self::SHA2_256 => 43,
            Self::Blake3_512 | Self::SHA3_512 | Self::Blake2B512 | Self::SHA2_512 => 86,
        }
    }

    fn soft_size(&self) -> usize {
        0
    }

    fn hard_size(&self) -> usize {
        match self {
            Self::Blake3_256
            | Self::Blake2B256(_)
            | Self::Blake2S256(_)
            | Self::SHA3_256
            | Self::SHA2_256 => 1,
            Self::Blake3_512 | Self::SHA3_512 | Self::Blake2B512 | Self::SHA2_512 => 2,
        }
    }

    fn to_str(&self) -> String {
        match self {
            Self::Blake3_256 => "E",
            Self::Blake2B256(_) => "F",
            Self::Blake2S256(_) => "G",
            Self::SHA3_256 => "H",
            Self::SHA2_256 => "I",
            Self::Blake3_512 => "0D",
            Self::SHA3_512 => "0E",
            Self::Blake2B512 => "0F",
            Self::SHA2_512 => "0G",
        }
        .into()
    }
}

impl FromStr for SelfAddressing {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.get(..1).ok_or_else(|| Error::EmptyCodeError)? {
            "E" => Ok(Self::Blake3_256),
            "F" => Ok(Self::Blake2B256(vec![])),
            "G" => Ok(Self::Blake2S256(vec![])),
            "H" => Ok(Self::SHA3_256),
            "I" => Ok(Self::SHA2_256),
            "0" => match &s[1..2] {
                "D" => Ok(Self::Blake3_512),
                "E" => Ok(Self::SHA3_512),
                "F" => Ok(Self::Blake2B512),
                "G" => Ok(Self::SHA2_512),
                _ => Err(Error::UnknownCodeError),
            },
            _ => Err(Error::UnknownCodeError),
        }
    }
}

pub fn dummy_prefix(derivation: &SelfAddressing) -> String {
    "#".repeat(derivation.code_size() + derivation.value_size())
}
