use std::str::FromStr;

use crate::event_parsing::error::Error;

use super::DerivationCode;

#[derive(Debug, PartialEq, Clone)]
pub enum SeedCode {
    RandomSeed128,
    RandomSeed256Ed25519,
    RandomSeed256ECDSAsecp256k1,
    RandomSeed448,
}

impl DerivationCode for SeedCode {
    fn value_size(&self) -> usize {
        match self {
            SeedCode::RandomSeed128 | SeedCode::RandomSeed256Ed25519 => 43,
            SeedCode::RandomSeed256ECDSAsecp256k1 => 75,
            SeedCode::RandomSeed448 => 22,
        }
    }

    fn soft_size(&self) -> usize {
        0
    }

    fn hard_size(&self) -> usize {
        match self {
            SeedCode::RandomSeed128 | SeedCode::RandomSeed256Ed25519 => 1,
            SeedCode::RandomSeed256ECDSAsecp256k1 => 1,
            SeedCode::RandomSeed448 => 2,
        }
    }

    fn to_str(&self) -> String {
        match self {
            Self::RandomSeed256Ed25519 => "A".to_string(),
            Self::RandomSeed256ECDSAsecp256k1 => "J".to_string(),
            Self::RandomSeed448 => "K".to_string(),
            Self::RandomSeed128 => "0A".to_string(),
        }
        .into()
    }
}

impl FromStr for SeedCode {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match &s[..1] {
            "A" => Ok(Self::RandomSeed256Ed25519),
            "J" => Ok(Self::RandomSeed256ECDSAsecp256k1),
            "K" => Ok(Self::RandomSeed448),
            "0" => match &s[1..2] {
                "A" => Ok(Self::RandomSeed128),
                _ => Err(Error::UnknownCodeError),
            },
            _ => Err(Error::UnknownCodeError),
        }
    }
}
