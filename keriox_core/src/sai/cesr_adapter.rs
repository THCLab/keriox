use std::str::FromStr;

use super::{SelfAddressing, SelfAddressingPrefix};

use crate::{
    event_parsing::{
        codes::{self_addressing::SelfAddressing as CesrSelfAddressing, DerivationCode},
        parsing::from_text_to_bytes,
    },
    prefix::{error::Error as PrefixError, Prefix},
};

impl Into<CesrSelfAddressing> for SelfAddressing {
    fn into(self) -> CesrSelfAddressing {
        match self {
            SelfAddressing::Blake3_256 => CesrSelfAddressing::Blake3_256,
            SelfAddressing::Blake2B256(a) => CesrSelfAddressing::Blake2B256(a),
            SelfAddressing::Blake2S256(a) => CesrSelfAddressing::Blake2S256(a),
            SelfAddressing::SHA3_256 => CesrSelfAddressing::SHA3_256,
            SelfAddressing::SHA2_256 => CesrSelfAddressing::SHA2_256,
            SelfAddressing::Blake3_512 => CesrSelfAddressing::Blake3_512,
            SelfAddressing::SHA3_512 => CesrSelfAddressing::SHA3_512,
            SelfAddressing::Blake2B512 => CesrSelfAddressing::Blake2B512,
            SelfAddressing::SHA2_512 => CesrSelfAddressing::SHA2_512,
        }
    }
}

impl From<CesrSelfAddressing> for SelfAddressing {
    fn from(csa: CesrSelfAddressing) -> Self {
        match csa {
            CesrSelfAddressing::Blake3_256 => SelfAddressing::Blake3_256,
            CesrSelfAddressing::Blake2B256(a) => SelfAddressing::Blake2B256(a),
            CesrSelfAddressing::Blake2S256(a) => SelfAddressing::Blake2S256(a),
            CesrSelfAddressing::SHA3_256 => SelfAddressing::SHA3_256,
            CesrSelfAddressing::SHA2_256 => SelfAddressing::SHA2_256,
            CesrSelfAddressing::Blake3_512 => SelfAddressing::Blake3_512,
            CesrSelfAddressing::SHA3_512 => SelfAddressing::SHA3_512,
            CesrSelfAddressing::Blake2B512 => SelfAddressing::Blake2B512,
            CesrSelfAddressing::SHA2_512 => SelfAddressing::SHA2_512,
        }
    }
}

impl Prefix for SelfAddressingPrefix {
    fn derivative(&self) -> Vec<u8> {
        self.digest.to_owned()
    }
    fn derivation_code(&self) -> String {
        let cesr_der: CesrSelfAddressing = self.derivation.clone().into();
        cesr_der.to_str()
    }
}

impl FromStr for SelfAddressingPrefix {
    type Err = PrefixError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let code = CesrSelfAddressing::from_str(s)?;
        let c_len = code.code_size();
        if s.len() == code.full_size() {
            let decoded = from_text_to_bytes(&s[c_len..].as_bytes())?[c_len..].to_vec();

            Ok(Self::new(code.into(), decoded))
        } else {
            Err(PrefixError::IncorrectLengthError(s.into()))
        }
    }
}
