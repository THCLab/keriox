use super::{self_signing::SelfSigning, DerivationCode};
use crate::event_parsing::{
    error::Error,
    parsing::{adjust_with_num, b64_to_num},
};
use core::str::FromStr;

/// Attached Signature Derivation Codes
///
/// A self signing prefix derivation outputs a signature as its derivative (2.3.5)
#[derive(Debug, PartialEq, Clone, Copy)]
pub struct AttachedSignatureCode {
    pub index: u16,
    pub code: SelfSigning,
}

impl AttachedSignatureCode {
    pub fn new(code: SelfSigning, index: u16) -> Self {
        Self { index, code }
    }
}

impl DerivationCode for AttachedSignatureCode {
    fn soft_size(&self) -> usize {
        match self.code {
            SelfSigning::Ed25519Sha512 | SelfSigning::ECDSAsecp256k1Sha256 => 1,
            SelfSigning::Ed448 => 2,
        }
    }

    fn hard_size(&self) -> usize {
        match self.code {
            SelfSigning::Ed25519Sha512 | SelfSigning::ECDSAsecp256k1Sha256 => 1,
            SelfSigning::Ed448 => 2,
        }
    }

    fn value_size(&self) -> usize {
        match self.code {
            SelfSigning::Ed25519Sha512 | SelfSigning::ECDSAsecp256k1Sha256 => 86,
            SelfSigning::Ed448 => 152,
        }
    }

    fn to_str(&self) -> String {
        [
            match self.code {
                SelfSigning::Ed25519Sha512 => "A",
                SelfSigning::ECDSAsecp256k1Sha256 => "B",
                SelfSigning::Ed448 => "0A",
            },
            &adjust_with_num(self.index, self.soft_size()),
        ]
        .join("")
    }
}

impl FromStr for AttachedSignatureCode {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match &s[..1] {
            "A" => Ok(Self::new(
                SelfSigning::Ed25519Sha512,
                b64_to_num(&s.as_bytes()[1..2])?,
            )),
            "B" => Ok(Self::new(
                SelfSigning::ECDSAsecp256k1Sha256,
                b64_to_num(&s.as_bytes()[1..2])?,
            )),
            "0" => match &s[1..2] {
                "A" => Ok(Self::new(
                    SelfSigning::Ed448,
                    b64_to_num(&s.as_bytes()[2..4])?,
                )),
                _ => Err(Error::UnknownCodeError),
            },
            _ => Err(Error::UnknownCodeError),
        }
    }
}
