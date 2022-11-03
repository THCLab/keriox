use super::{self_signing::SelfSigning, DerivationCode};
use crate::event_parsing::{
    error::Error,
    parsing::{b64_to_num, num_to_b64},
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
    // TODO, this will only work with indicies up to 63
    fn to_str(&self) -> String {
        [
            match self.code {
                SelfSigning::Ed25519Sha512 => "A",
                SelfSigning::ECDSAsecp256k1Sha256 => "B",
                SelfSigning::Ed448 => "0AA",
            },
            &num_to_b64(self.index),
        ]
        .join("")
    }

    fn code_len(&self) -> usize {
        match self.code {
            SelfSigning::Ed25519Sha512 | SelfSigning::ECDSAsecp256k1Sha256 => 2,
            SelfSigning::Ed448 => 4,
        }
    }

    fn derivative_b64_len(&self) -> usize {
        match self.code {
            SelfSigning::Ed25519Sha512 | SelfSigning::ECDSAsecp256k1Sha256 => 86,
            SelfSigning::Ed448 => 152,
        }
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
            "0" => match &s[1..3] {
                "AA" => Ok(Self::new(
                    SelfSigning::Ed448,
                    b64_to_num(&s.as_bytes()[3..4])?,
                )),
                _ => Err(Error::UnknownCodeError),
            },
            _ => Err(Error::UnknownCodeError),
        }
    }
}
