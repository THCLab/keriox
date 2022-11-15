use std::str::FromStr;

use nom::multi::many0;

use self::{
    attached_signature_code::AttachedSignatureCode,
    basic::Basic,
    group::GroupCode,
    self_addressing::SelfAddressing,
    self_signing::SelfSigning,
    serial_number::{pack_sn, SerialNumberCode},
};

pub mod attached_signature_code;
pub mod basic;
pub mod group;
pub mod material_path_codes;
pub mod self_addressing;
pub mod self_signing;
pub mod serial_number;

use super::{
    error::Error,
    message::event_message,
    parsers::group::parse_group,
    primitives::{
        CesrPrimitive, Digest, IdentifierSignaturesCouple, IndexedSignature, PublicKey, Signature,
        Timestamp, TransferableQuadruple,
    },
    EventType,
};

pub trait DerivationCode {
    /// hard (fixed) part of code size in chars
    fn hard_size(&self) -> usize;
    /// soft (variable) part of code size in chars
    fn soft_size(&self) -> usize;
    /// value size in charsi
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
    // todo
    Seed(),
    Basic(Basic),
    SelfAddressing(SelfAddressing),
    SelfSigning(SelfSigning),
    SerialNumber(SerialNumberCode),
    IndexedSignature(AttachedSignatureCode),
    Timestamp,
}

impl PrimitiveCode {
    pub fn to_str(&self) -> String {
        match self {
            PrimitiveCode::Basic(code) => code.to_str(),
            PrimitiveCode::SelfAddressing(code) => code.to_str(),
            PrimitiveCode::SelfSigning(code) => code.to_str(),
            PrimitiveCode::SerialNumber(code) => code.to_str(),
            PrimitiveCode::IndexedSignature(code) => code.to_str(),
            PrimitiveCode::Timestamp => todo!(),
            PrimitiveCode::Seed() => todo!(),
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
            PrimitiveCode::Seed() => todo!(),
            PrimitiveCode::Basic(b) => b.hard_size(),
            PrimitiveCode::SelfAddressing(sa) => sa.hard_size(),
            PrimitiveCode::SelfSigning(ss) => ss.hard_size(),
            PrimitiveCode::SerialNumber(sn) => sn.hard_size(),
            PrimitiveCode::IndexedSignature(i) => i.hard_size(),
            PrimitiveCode::Timestamp => todo!(),
        }
    }

    fn soft_size(&self) -> usize {
        match self {
            PrimitiveCode::Seed() => todo!(),
            PrimitiveCode::Basic(b) => b.soft_size(),
            PrimitiveCode::SelfAddressing(sa) => sa.soft_size(),
            PrimitiveCode::SelfSigning(ss) => ss.soft_size(),
            PrimitiveCode::SerialNumber(sn) => sn.soft_size(),
            PrimitiveCode::IndexedSignature(i) => i.soft_size(),
            PrimitiveCode::Timestamp => todo!(),
        }
    }

    fn value_size(&self) -> usize {
        match self {
            PrimitiveCode::Seed() => todo!(),
            PrimitiveCode::Basic(b) => b.value_size(),
            PrimitiveCode::SelfAddressing(sa) => sa.value_size(),
            PrimitiveCode::SelfSigning(ss) => ss.value_size(),
            PrimitiveCode::SerialNumber(sn) => sn.value_size(),
            PrimitiveCode::IndexedSignature(i) => i.value_size(),
            PrimitiveCode::Timestamp => todo!(),
        }
    }

    fn to_str(&self) -> String {
        match self {
            PrimitiveCode::Seed() => todo!(),
            PrimitiveCode::Basic(b) => b.to_str(),
            PrimitiveCode::SelfAddressing(sa) => sa.to_str(),
            PrimitiveCode::SelfSigning(ss) => ss.to_str(),
            PrimitiveCode::SerialNumber(sn) => sn.to_str(),
            PrimitiveCode::IndexedSignature(i) => i.to_str(),
            PrimitiveCode::Timestamp => todo!(),
        }
    }
}

impl Group {
    pub fn to_cesr_str(&self) -> String {
        [self.code(), self.data_to_str()].join("")
    }
    fn data_to_str(&self) -> String {
        match self {
            Group::IndexedControllerSignatures(sigs) | Group::IndexedWitnessSignatures(sigs) => {
                sigs.iter()
                    .fold("".into(), |acc, s| [acc, s.to_str()].join(""))
            }
            Group::NontransferableReceiptCouples(couples) => {
                couples
                    .iter()
                    .fold("".into(), |acc, (identifeir, signature)| {
                        [acc, identifeir.to_str(), signature.to_str()].join("")
                    })
            }
            Group::SourceSealCouples(quadruple) => {
                quadruple.into_iter().fold("".into(), |acc, (sn, digest)| {
                    // let signatures = signatures.iter().fold("".into(), |acc, s| {
                    //     [acc, s.to_str()].join("")
                    // });
                    [acc, "0A".to_string(), pack_sn(*sn), digest.to_str()].join("")
                })
            }
            Group::FirstSeenReplyCouples(couples) => {
                couples.iter().fold("".into(), |acc, (sn, dt)| {
                    [acc, "0A".to_string(), pack_sn(*sn), todo!()].join("")
                })
            }
            Group::TransferableIndexedSigGroups(groups) => {
                groups
                    .iter()
                    .fold("".into(), |acc, (identifier, sn, digest, signatures)| {
                        let signatures = signatures
                            .iter()
                            .fold("".into(), |acc, s| [acc, s.to_str()].join(""));
                        [
                            acc,
                            identifier.to_str(),
                            "0A".to_string(),
                            pack_sn(*sn),
                            digest.to_str(),
                            signatures,
                        ]
                        .join("")
                    })
            }
            Group::LastEstSignaturesGroups(couples) => {
                couples
                    .iter()
                    .fold("".into(), |acc, (identifier, signatures)| {
                        let signatures = signatures
                            .iter()
                            .fold("".into(), |acc, s| [acc, s.to_str()].join(""));
                        [acc, identifier.to_str(), signatures].join("")
                    })
            }
            Group::Frame(_) => todo!(),
            Group::PathedMaterialQuadruplet(_) => todo!(),
        }
    }

    fn code(&self) -> String {
        match self {
            Group::IndexedControllerSignatures(sigs) => {
                GroupCode::IndexedControllerSignatures(sigs.len() as u16)
            }
            Group::IndexedWitnessSignatures(sigs) => {
                GroupCode::IndexedWitnessSignatures(sigs.len() as u16)
            }
            Group::NontransferableReceiptCouples(couples) => {
                GroupCode::NontransferableReceiptCouples(couples.len() as u16)
            }
            Group::SourceSealCouples(couple) => GroupCode::SealSourceCouples(couple.len() as u16),
            Group::FirstSeenReplyCouples(couple) => {
                GroupCode::FirstSeenReplyCouples(couple.len() as u16)
            }
            Group::TransferableIndexedSigGroups(group) => {
                GroupCode::TransferableIndexedSigGroups(group.len() as u16)
            }
            Group::LastEstSignaturesGroups(group) => {
                GroupCode::LastEstSignaturesGroups(group.len() as u16)
            }
            Group::Frame(_) => todo!(),
            Group::PathedMaterialQuadruplet(_) => todo!(),
        }
        .to_str()
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum Group {
    IndexedControllerSignatures(Vec<IndexedSignature>),
    IndexedWitnessSignatures(Vec<IndexedSignature>),
    NontransferableReceiptCouples(Vec<(PublicKey, Signature)>),
    SourceSealCouples(Vec<(u64, Digest)>),
    // todo add timestamp
    FirstSeenReplyCouples(Vec<(u64, Timestamp)>),
    TransferableIndexedSigGroups(Vec<TransferableQuadruple>),
    LastEstSignaturesGroups(Vec<IdentifierSignaturesCouple>),

    // todo
    Frame(u16),
    // it's from cesr-proof
    PathedMaterialQuadruplet(u16),
}

pub struct ParsedData {
    payload: EventType,
    attachments: Vec<Group>,
}

pub fn parse_payload(stream: &[u8]) -> nom::IResult<&[u8], EventType> {
    event_message(stream)
}

pub fn parse(stream: &[u8]) -> nom::IResult<&[u8], ParsedData> {
    let (rest, payload) = parse_payload(stream)?;
    let (rest, attachments) = many0(parse_group)(rest)?;

    Ok((
        rest,
        ParsedData {
            payload,
            attachments,
        },
    ))
}
