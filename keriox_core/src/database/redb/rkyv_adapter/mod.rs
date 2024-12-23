use rkyv::{util::AlignedVec, with::With};
use said::SelfAddressingIdentifier;
use said_wrapper::{ArchivedSAIDef, SAIDef};

use crate::{event_message::signature::{ArchivedNontransferable, Nontransferable}, prefix::{attached_signature::ArchivedIndexedSignature, IndexedSignature}};

pub(crate) mod said_wrapper;
pub(crate) mod serialization_info_wrapper;

pub fn serialize_said(said: &SelfAddressingIdentifier) -> Result<AlignedVec, rkyv::rancor::Failure> {
		Ok(rkyv::to_bytes(With::<SelfAddressingIdentifier, SAIDef>::cast(said))?)

}

pub fn deserialize_said(bytes: &[u8]) -> Result<SelfAddressingIdentifier, rkyv::rancor::Failure> {
	let archived: &ArchivedSAIDef = rkyv::access(&bytes)?;
	let deserialized: SelfAddressingIdentifier = rkyv::deserialize(With::<ArchivedSAIDef, SAIDef>::cast(archived))?;
	Ok(deserialized)
}

pub fn deserialize_nontransferable(bytes: &[u8]) -> Result<Nontransferable, rkyv::rancor::Failure> {
	let archived = rkyv::access::<ArchivedNontransferable, rkyv::rancor::Failure>(&bytes).unwrap();
    rkyv::deserialize::<Nontransferable, rkyv::rancor::Failure>(archived)
}

pub fn deserialize_indexed_signatures(bytes: &[u8]) -> Result<IndexedSignature, rkyv::rancor::Failure> {
	let archived = rkyv::access::<ArchivedIndexedSignature, rkyv::rancor::Failure>(&bytes).unwrap();
    rkyv::deserialize::<IndexedSignature, rkyv::rancor::Failure>(archived)
}