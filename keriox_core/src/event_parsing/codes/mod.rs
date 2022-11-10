use nom::{
    bytes::complete::take,
    multi::{count, many0},
    sequence::tuple,
};

use self::{
    attached_signature_code::AttachedSignatureCode, basic::Basic, group::GroupCode,
    self_addressing::SelfAddressing, self_signing::SelfSigning, serial_number::{pack_sn, SerialNumberCode},
};

pub mod attached_signature_code;
pub mod basic;
pub mod group;
pub mod material_path_codes;
pub mod self_addressing;
pub mod self_signing;
pub mod serial_number;

use super::{
    message::event_message,
    parsers::{
        group_code, identifier_signature_pair, indexed_signature, nontransferable_identifier,
        serial_number_parser, signature, timestamp, transferable_quadruple,
    },
    parsing::{from_text_to_bytes},
    EventType, primitives::{IndexedSignature, NontransferableIdentifier, TransferableQuadruple, Timestamp, CesrPrimitive, Signature, IdentifierSignaturesCouple},
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

pub fn parse_value<A: DerivationCode>(code: A, stream: &[u8]) -> nom::IResult<&[u8], (A, Vec<u8>)> {
    let (rest, data) = take(code.value_size() as usize)(stream)?;
    let decoded = from_text_to_bytes(data).unwrap()[code.code_size()..].to_vec();
    Ok((rest, (code, decoded)))
}

pub enum PrimitiveCode {
    // todo
    Seed(),
    Basic(Basic),
    SelfAddressing(SelfAddressing),
    SelfSigning(SelfSigning),
    SerialNumber(SerialNumberCode),
    IndexedSignature(AttachedSignatureCode),
    Timestamp
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

impl Group {
    pub fn to_cesr_str(&self) -> String {
        [self.code(), self.data_to_str()].join("")
    }
    fn data_to_str(&self) -> String {
        match self {
            Group::IndexedControllerSignatures(sigs) | Group::IndexedWitnessSignatures(sigs) => {
                sigs.iter().fold("".into(), |acc, s| {
                    [acc, s.to_str()].join("")
                })
            }
            Group::NontransferableReceiptCouples(couples) => 
                couples.iter().fold("".into(), |acc, (identifeir, signature)| {
                    [acc, identifeir.to_str(), signature.to_str()].join("")
                }),
            Group::TransferableReceiptQuadruples(quadruple) => {
                quadruple.into_iter().fold("".into(), |acc, (identifeir, sn, digest, signatures)| {
                    let signatures = signatures.iter().fold("".into(), |acc, s| {
                        [acc, s.to_str()].join("")
                    });
                    [acc, identifeir.to_str(), "0A".to_string(), pack_sn(*sn), digest.to_str(), signatures].join("")
                })
            },
            Group::FirstSeenReplyCouples(couples) => {
                couples.iter().fold("".into(), |acc, (sn, dt)| {
                    [acc, "0A".to_string(), pack_sn(*sn), "todo".to_string()].join("")
                })
            },
            Group::TransferableIndexedSigGroups(groups) => {
                groups.iter().fold("".into(), |acc, (identifier, sn, digest, signatures)| {
                    let signatures = signatures.iter().fold("".into(), |acc, s| {
                        [acc, s.to_str()].join("")
                    });
                    [acc, identifier.to_str(), "0A".to_string(), pack_sn(*sn), signatures].join("")
                })
            },
            Group::LastEstSignaturesGroups(couples) => {
                couples.iter().fold("".into(), |acc, (identifier, signatures)| {
                    let signatures = signatures.iter().fold("".into(), |acc, s| {
                        [acc, s.to_str()].join("")
                    });
                    [acc, identifier.to_str(), signatures].join("")
                })
            },
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
            Group::TransferableReceiptQuadruples(quadruple) => {
                GroupCode::TransferableReceiptQuadruples(quadruple.len() as u16)
            }
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
    NontransferableReceiptCouples(Vec<(NontransferableIdentifier, Signature)>),
    TransferableReceiptQuadruples(Vec<TransferableQuadruple>),
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

pub fn parse_group(stream: &[u8]) -> nom::IResult<&[u8], Group> {
    let (rest, group_code) = group_code(stream)?;
    Ok(match group_code {
        GroupCode::IndexedControllerSignatures(n) => {
            let (rest, signatures) = count(indexed_signature, n as usize)(rest)?;
            (rest, Group::IndexedControllerSignatures(signatures))
        }
        GroupCode::IndexedWitnessSignatures(n) => {
            let (rest, signatures) = count(indexed_signature, n as usize)(rest)?;
            (rest, Group::IndexedWitnessSignatures(signatures))
        }
        GroupCode::NontransferableReceiptCouples(n) => {
            let (rest, couple) =
                count(tuple((nontransferable_identifier, signature)), n as usize)(rest)?;
            (rest, Group::NontransferableReceiptCouples(couple))
        }
        GroupCode::TransferableReceiptQuadruples(n) => {
            let (rest, quadruple) = count(transferable_quadruple, n as usize)(rest).unwrap();
            (rest, Group::TransferableReceiptQuadruples(quadruple))
        }
        GroupCode::FirstSeenReplyCouples(n) => {
            let (rest, couple) = count(tuple((serial_number_parser, timestamp)), n as usize)(rest)?;
            (rest, Group::FirstSeenReplyCouples(couple))
        }
        GroupCode::TransferableIndexedSigGroups(n) => {
            let (rest, quadruple) = count(transferable_quadruple, n as usize)(rest).unwrap();
            (rest, Group::TransferableIndexedSigGroups(quadruple))
        }
        GroupCode::LastEstSignaturesGroups(n) => {
            let (rest, couple) = count(identifier_signature_pair, n as usize)(rest)?;
            (rest, Group::LastEstSignaturesGroups(couple))
        }
        GroupCode::Frame(_) => todo!(),
        GroupCode::PathedMaterialQuadruplet(_) => todo!(),
    })
}

pub fn parse(stream: &[u8]) -> nom::IResult<&[u8], ParsedData> {
    let (rest, payload) = event_message(stream)?;
    let (rest, attachments) = many0(parse_group)(rest)?;

    Ok((
        rest,
        ParsedData {
            payload,
            attachments,
        },
    ))
}
