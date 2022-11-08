use chrono::{FixedOffset, DateTime};
use nom::{bytes::complete::take, multi::{count, many0}, sequence::tuple};

use self::{basic::Basic, self_signing::SelfSigning, group::GroupCode, attached_signature_code::AttachedSignatureCode, self_addressing::SelfAddressing};

pub mod attached_signature_code;
pub mod basic;
pub mod group;
pub mod material_path_codes;
pub mod self_addressing;
pub mod self_signing;
pub mod serial_number;

use super::{message::event_message, parsers::{group_code, indexed_signature, nontransferable_identifier, signature, serial_number_parser, transferable_quadruple, timestamp, identifier_signature_pair}, EventType, parsing::from_text_to_bytes};

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

pub enum Codes {
    Primitives(IdentifierCode),
    GroupCode(GroupCode),
}

pub enum IdentifierCode {
    Basic(Basic),
    SelfAddressing(SelfAddressing),
}

pub type Identifier = (IdentifierCode, Vec<u8>);
pub type NontransferableIdentifier = (Basic, Vec<u8>);
pub type Digest = (SelfAddressing, Vec<u8>);
pub type Signature = (SelfSigning, Vec<u8>);
pub type IndexedSignature = (AttachedSignatureCode, Vec<u8>);
pub type Timestamp = DateTime<FixedOffset>;
pub type TransferableQuadruple = (Identifier, u64, Digest, Vec<IndexedSignature>);
pub type IdentifierSignaturesCouple = (Identifier, Vec<IndexedSignature>);

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
    attachments: Vec<Group>
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
        },
        GroupCode::IndexedWitnessSignatures(n) => {
            let (rest, signatures) = count(indexed_signature, n as usize)(rest)?;
            (rest, Group::IndexedWitnessSignatures(signatures))
        },
        GroupCode::NontransferableReceiptCouples(n) => {
            let (rest, couple) = count(tuple((nontransferable_identifier, signature)), n as usize)(rest)?;
            (rest, Group::NontransferableReceiptCouples(couple))
        },
        GroupCode::TransferableReceiptQuadruples(n) => {
            let (rest, quadruple) = count(
                transferable_quadruple, n as usize)(rest).unwrap();
            (rest, Group::TransferableReceiptQuadruples(quadruple))
        },
        GroupCode::FirstSeenReplyCouples(n) => {
            let (rest, couple) = count(tuple((serial_number_parser, timestamp)), n as usize)(rest)?;
            (rest, Group::FirstSeenReplyCouples(couple))
        },
        GroupCode::TransferableIndexedSigGroups(n) => {
            let (rest, quadruple) = count(
                transferable_quadruple, n as usize)(rest).unwrap();
            (rest, Group::TransferableIndexedSigGroups(quadruple))
        },
        GroupCode::LastEstSignaturesGroups(n) => {
            let (rest, couple) = count(identifier_signature_pair, n as usize)(rest)?;
            (rest, Group::LastEstSignaturesGroups(couple))
        },
        GroupCode::Frame(_) => todo!(),
        GroupCode::PathedMaterialQuadruplet(_) => todo!(),
    })
}

pub fn parse(stream: &[u8]) -> nom::IResult<&[u8], ParsedData> { 
    let (rest, payload) = event_message(stream)?;
    let (rest, attachments) = many0(parse_group)(rest)?;


    Ok((rest, ParsedData {payload, attachments}))
}