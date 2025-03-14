use rkyv::{util::AlignedVec, with::With};
use said::SelfAddressingIdentifier;
use said_wrapper::{ArchivedSAIDef, SAIDef};

use crate::{
    event::sections::seal::{ArchivedSourceSeal, SourceSeal},
    event_message::signature::{
        ArchivedNontransferable, ArchivedTransferable, Nontransferable, Transferable,
    },
    prefix::{attached_signature::ArchivedIndexedSignature, IndexedSignature},
    state::IdentifierState,
};

pub(crate) mod said_wrapper;
pub(crate) mod serialization_info_wrapper;

pub fn serialize_said(said: &SelfAddressingIdentifier) -> Result<AlignedVec, rkyv::rancor::Error> {
    Ok(rkyv::to_bytes(
        With::<SelfAddressingIdentifier, SAIDef>::cast(said),
    )?)
}

pub fn deserialize_said(bytes: &[u8]) -> Result<SelfAddressingIdentifier, rkyv::rancor::Error> {
    let archived: &ArchivedSAIDef = rkyv::access(&bytes)?;
    let deserialized: SelfAddressingIdentifier =
        rkyv::deserialize(With::<ArchivedSAIDef, SAIDef>::cast(archived))?;
    Ok(deserialized)
}

pub fn deserialize_nontransferable(bytes: &[u8]) -> Result<Nontransferable, rkyv::rancor::Error> {
    let archived = rkyv::access::<ArchivedNontransferable, rkyv::rancor::Failure>(&bytes).unwrap();
    rkyv::deserialize::<Nontransferable, rkyv::rancor::Error>(archived)
}

pub fn deserialize_transferable(bytes: &[u8]) -> Result<Transferable, rkyv::rancor::Error> {
    let archived = rkyv::access::<ArchivedTransferable, rkyv::rancor::Failure>(&bytes).unwrap();
    rkyv::deserialize::<Transferable, rkyv::rancor::Error>(archived)
}

pub fn deserialize_indexed_signatures(
    bytes: &[u8],
) -> Result<IndexedSignature, rkyv::rancor::Error> {
    let archived = rkyv::access::<ArchivedIndexedSignature, rkyv::rancor::Error>(&bytes).unwrap();
    rkyv::deserialize::<IndexedSignature, rkyv::rancor::Error>(archived)
}

pub fn deserialize_source_seal(bytes: &[u8]) -> Result<SourceSeal, rkyv::rancor::Error> {
    let archived = rkyv::access::<ArchivedSourceSeal, rkyv::rancor::Error>(&bytes).unwrap();
    rkyv::deserialize::<SourceSeal, rkyv::rancor::Error>(archived)
}

pub fn deserialize_identifier_state(bytes: &[u8]) -> Result<IdentifierState, rkyv::rancor::Error> {
    let mut aligned_bytes =
        AlignedVec::<{ std::mem::align_of::<IdentifierState>() }>::with_capacity(bytes.len());
    aligned_bytes.extend_from_slice(bytes);

    rkyv::from_bytes::<IdentifierState, rkyv::rancor::Error>(&aligned_bytes)
}
