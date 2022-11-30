use std::str::FromStr;

use self::{
    attached_signature_code::AttachedSignatureCode, basic::Basic, seed::SeedCode,
    self_addressing::SelfAddressing, self_signing::SelfSigning, serial_number::SerialNumberCode,
    timestamp::TimestampCode,
};

pub mod attached_signature_code;
pub mod basic;
pub mod group;
pub mod material_path_codes;
pub mod seed;
pub mod self_addressing;
pub mod self_signing;
pub mod serial_number;
pub mod timestamp;

use super::error::Error;

pub trait DerivationCode {
    /// hard (fixed) part of code size in chars
    fn hard_size(&self) -> usize;
    /// soft (variable) part of code size in chars
    fn soft_size(&self) -> usize;
    /// value size in chars
    fn value_size(&self) -> usize;

    fn code_size(&self) -> usize {
        self.hard_size() + self.soft_size()
    }
    /// full size in chars of code prefixed to data
    fn full_size(&self) -> usize {
        self.code_size() + self.value_size()
    }
    fn to_str(&self) -> String;
}

#[derive(PartialEq, Debug)]
pub enum PrimitiveCode {
    Seed(SeedCode),
    Basic(Basic),
    SelfAddressing(SelfAddressing),
    SelfSigning(SelfSigning),
    SerialNumber(SerialNumberCode),
    IndexedSignature(AttachedSignatureCode),
    Timestamp(TimestampCode),
}

impl PrimitiveCode {
    pub fn to_str(&self) -> String {
        match self {
            PrimitiveCode::Basic(code) => code.to_str(),
            PrimitiveCode::SelfAddressing(code) => code.to_str(),
            PrimitiveCode::SelfSigning(code) => code.to_str(),
            PrimitiveCode::SerialNumber(code) => code.to_str(),
            PrimitiveCode::IndexedSignature(code) => code.to_str(),
            PrimitiveCode::Timestamp(code) => code.to_str(),
            PrimitiveCode::Seed(code) => code.to_str(),
        }
    }
}

impl FromStr for PrimitiveCode {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match AttachedSignatureCode::from_str(s) {
            Ok(sig) => Ok(PrimitiveCode::IndexedSignature(sig)),
            Err(_) => match Basic::from_str(s) {
                Ok(bp) => Ok(PrimitiveCode::Basic(bp)),
                Err(_) => match SelfAddressing::from_str(s) {
                    Ok(sa) => Ok(PrimitiveCode::SelfAddressing(sa)),
                    Err(_) => match SelfSigning::from_str(s) {
                        Ok(ss) => Ok(PrimitiveCode::SelfSigning(ss)),
                        Err(_) => match SerialNumberCode::from_str(s) {
                            Ok(sn) => Ok(PrimitiveCode::SerialNumber(sn)),
                            Err(_) => todo!(),
                        },
                    },
                },
            },
        }
    }
}

impl DerivationCode for PrimitiveCode {
    fn hard_size(&self) -> usize {
        match self {
            PrimitiveCode::Seed(s) => s.hard_size(),
            PrimitiveCode::Basic(b) => b.hard_size(),
            PrimitiveCode::SelfAddressing(sa) => sa.hard_size(),
            PrimitiveCode::SelfSigning(ss) => ss.hard_size(),
            PrimitiveCode::SerialNumber(sn) => sn.hard_size(),
            PrimitiveCode::IndexedSignature(i) => i.hard_size(),
            PrimitiveCode::Timestamp(code) => code.hard_size(),
        }
    }

    fn soft_size(&self) -> usize {
        match self {
            PrimitiveCode::Seed(s) => s.soft_size(),
            PrimitiveCode::Basic(b) => b.soft_size(),
            PrimitiveCode::SelfAddressing(sa) => sa.soft_size(),
            PrimitiveCode::SelfSigning(ss) => ss.soft_size(),
            PrimitiveCode::SerialNumber(sn) => sn.soft_size(),
            PrimitiveCode::IndexedSignature(i) => i.soft_size(),
            PrimitiveCode::Timestamp(code) => code.soft_size(),
        }
    }

    fn value_size(&self) -> usize {
        match self {
            PrimitiveCode::Seed(s) => s.value_size(),
            PrimitiveCode::Basic(b) => b.value_size(),
            PrimitiveCode::SelfAddressing(sa) => sa.value_size(),
            PrimitiveCode::SelfSigning(ss) => ss.value_size(),
            PrimitiveCode::SerialNumber(sn) => sn.value_size(),
            PrimitiveCode::IndexedSignature(i) => i.value_size(),
            PrimitiveCode::Timestamp(code) => code.value_size(),
        }
    }

    fn to_str(&self) -> String {
        match self {
            PrimitiveCode::Seed(s) => s.to_str(),
            PrimitiveCode::Basic(b) => b.to_str(),
            PrimitiveCode::SelfAddressing(sa) => sa.to_str(),
            PrimitiveCode::SelfSigning(ss) => ss.to_str(),
            PrimitiveCode::SerialNumber(sn) => sn.to_str(),
            PrimitiveCode::IndexedSignature(i) => i.to_str(),
            PrimitiveCode::Timestamp(code) => code.to_str(),
        }
    }
}
