use super::error::Error;
use super::SelfSigningPrefix;
use cesrox::{
    conversion::from_text_to_bytes,
    derivation_code::DerivationCode,
    primitives::{
        codes::{
            attached_signature_code::AttachedSignatureCode, self_signing::SelfSigning,
            PrimitiveCode,
        },
        CesrPrimitive,
    },
};
use core::str::FromStr;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[derive(Debug, PartialEq, Clone)]
pub enum Index {
    CurrentOnly(u16),
    BothSame(u16),
    BothDifferent(u16, u16),
}

impl Index {
    pub fn current(&self) -> u16 {
        *match self {
            Index::CurrentOnly(current) => current,
            Index::BothSame(current) => current,
            Index::BothDifferent(current, _prev_next) => current,
        }
    }

    pub fn previous_next(&self) -> Option<u16> {
        match self {
            Index::CurrentOnly(_) => None,
            Index::BothSame(prev_next) => Some(*prev_next),
            Index::BothDifferent(_, prev_next) => Some(*prev_next),
        }
    }
}
#[derive(Debug, PartialEq, Clone)]
pub struct IndexedSignature {
    pub index: Index,
    pub signature: SelfSigningPrefix,
}

impl IndexedSignature {
    pub fn new_both_same(signature: SelfSigningPrefix, index: u16) -> Self {
        Self {
            signature,
            index: Index::BothSame(index),
        }
    }

    pub fn new_both_diffrent(
        signature: SelfSigningPrefix,
        curr_index: u16,
        prev_next_index: u16,
    ) -> Self {
        Self {
            signature,
            index: Index::BothDifferent(curr_index, prev_next_index),
        }
    }

    pub fn new_current_only(signature: SelfSigningPrefix, curr_index: u16) -> Self {
        Self {
            index: Index::CurrentOnly(curr_index),
            signature,
        }
    }
}

impl FromStr for IndexedSignature {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let code = AttachedSignatureCode::from_str(s)?;

        if (s.len()) == code.full_size() {
            let lead = if code.code_size() % 4 != 0 {
                code.code_size() % 4
            } else {
                0
            };
            let s_vec = from_text_to_bytes(&s[code.code_size()..].as_bytes())?[lead..].to_vec();
            let ssp = SelfSigningPrefix::new(code.code, s_vec);

            Ok(Self {
                index: code.index.into(),
                signature: ssp,
            })
        } else {
            Err(Error::IncorrectLengthError(s.into()))
        }
    }
}

impl CesrPrimitive for IndexedSignature {
    fn derivative(&self) -> Vec<u8> {
        self.signature.derivative()
    }
    fn derivation_code(&self) -> PrimitiveCode {
        let code: SelfSigning = self.signature.get_code();
        PrimitiveCode::IndexedSignature(AttachedSignatureCode::new(code, (&self.index).into()))
    }
}

/// Serde compatible Serialize
impl Serialize for IndexedSignature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_str())
    }
}

/// Serde compatible Deserialize
impl<'de> Deserialize<'de> for IndexedSignature {
    fn deserialize<D>(deserializer: D) -> Result<IndexedSignature, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;

        IndexedSignature::from_str(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deserialize() -> Result<(), Error> {
        let attached_ed_1 = "ABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let attached_secp_2 = "BCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let attached_448_3 = "0AADAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

        let pref_ed_1 = IndexedSignature::from_str(attached_ed_1)?;
        let pref_secp_2 = IndexedSignature::from_str(attached_secp_2)?;
        let pref_448_3 = IndexedSignature::from_str(attached_448_3)?;

        assert_eq!(1, pref_ed_1.index.current());
        assert_eq!(2, pref_secp_2.index.current());
        assert_eq!(0, pref_448_3.index.current());
        assert_eq!(Some(3), pref_448_3.index.previous_next());

        assert_eq!(SelfSigning::Ed25519Sha512, pref_ed_1.signature.get_code());
        assert_eq!(SelfSigning::Ed25519Sha512, pref_secp_2.signature.get_code());
        assert_eq!(SelfSigning::Ed448, pref_448_3.signature.get_code());
        Ok(())
    }

    #[test]
    fn serialize() -> Result<(), Error> {
        let pref_ed_2 =
            IndexedSignature::new_both_same(SelfSigningPrefix::Ed25519Sha512(vec![0u8; 64]), 2);
        let pref_ed_2_3 = IndexedSignature::new_both_diffrent(
            SelfSigningPrefix::Ed25519Sha512(vec![0u8; 64]),
            2,
            3,
        );
        let pref_secp_6 = IndexedSignature::new_both_same(
            SelfSigningPrefix::ECDSAsecp256k1Sha256(vec![0u8; 64]),
            6,
        );
        let pref_448_4 =
            IndexedSignature::new_both_diffrent(SelfSigningPrefix::Ed448(vec![0u8; 114]), 0, 4);

        assert_eq!(88, pref_ed_2.to_str().len());
        assert_eq!(88, pref_secp_6.to_str().len());
        assert_eq!(156, pref_448_4.to_str().len());

        assert_eq!("ACAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", pref_ed_2.to_str());
        assert_eq!("2AACADAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", pref_ed_2_3.to_str());
        assert_eq!("CGAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", pref_secp_6.to_str());
        assert_eq!("0AAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", pref_448_4.to_str());
        Ok(())
    }
}
