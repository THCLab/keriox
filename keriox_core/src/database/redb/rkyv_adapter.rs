use said::{derivation::{HashFunction, HashFunctionCode}, SelfAddressingIdentifier};

use rkyv::{with::With, Archive, Deserialize, Serialize};
use rkyv::util::AlignedVec;

use crate::{event_message::signature::{ArchivedNontransferable, Nontransferable}, prefix::{attached_signature::ArchivedIndexedSignature, IndexedSignature}};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, Default, Eq, Hash)]
#[derive(Archive, rkyv::Serialize, rkyv::Deserialize, PartialEq)]
pub(crate) struct SaidValue {
	#[rkyv(with = SAIDef)]
	said: SelfAddressingIdentifier
}

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

#[derive(Archive, Serialize, Deserialize)]
#[rkyv(remote = SelfAddressingIdentifier)] 
pub(crate) struct SAIDef {
	#[rkyv(with = HashFunctionDef)]
	pub derivation: HashFunction,
	pub digest: Vec<u8>,
}

// Deriving `Deserialize` with `remote = ..` requires a `From` implementation.
impl From<SAIDef> for SelfAddressingIdentifier {
	fn from(value: SAIDef) -> Self {
		Self::new(value.derivation, value.digest)
	}
}

#[derive(Archive, Serialize, Deserialize)]
#[rkyv(remote = HashFunction)]
struct HashFunctionDef { 
	#[rkyv(getter = HashFunctionDef::get_code, with = HashFunctionCodeDef)]
	pub f: HashFunctionCode
}

impl HashFunctionDef {
	fn get_code(foo: &HashFunction) -> HashFunctionCode {
		foo.into()
	}

}    

// Deriving `Deserialize` with `remote = ..` requires a `From` implementation.
impl From<HashFunctionDef> for HashFunction {
	fn from(value: HashFunctionDef) -> Self {
	   value.f.into() 
	}
}

#[derive(Archive, Serialize, Deserialize)]
#[rkyv(remote = HashFunctionCode)] 
enum HashFunctionCodeDef {
	Blake3_256,
	Blake2B256(Vec<u8>),
	Blake2S256(Vec<u8>),
	SHA3_256,
	SHA2_256,
	Blake3_512,
	SHA3_512,
	Blake2B512,
	SHA2_512,
}

impl From<HashFunctionCodeDef> for HashFunctionCode {
	fn from(value: HashFunctionCodeDef) -> Self {
		match value {
			HashFunctionCodeDef::Blake3_256 => HashFunctionCode::Blake3_256,
			HashFunctionCodeDef::Blake2B256(vec) => HashFunctionCode::Blake2B256(vec),
			HashFunctionCodeDef::Blake2S256(vec) => HashFunctionCode::Blake2S256(vec),
			HashFunctionCodeDef::SHA3_256 => HashFunctionCode::SHA3_256,
			HashFunctionCodeDef::SHA2_256 => HashFunctionCode::SHA2_256,
			HashFunctionCodeDef::Blake3_512 => HashFunctionCode::Blake3_512,
			HashFunctionCodeDef::SHA3_512 => HashFunctionCode::SHA3_512,
			HashFunctionCodeDef::Blake2B512 => HashFunctionCode::Blake2B512,
			HashFunctionCodeDef::SHA2_512 => HashFunctionCode::SHA2_512,
		}
	}
}

#[test]
fn test_rkyv_said_serialization() -> Result<(), rkyv::rancor::Failure> {
	let value: SelfAddressingIdentifier = "EJe_sKQb1otKrz6COIL8VFvBv3DEFvtKaVFGn1vm0IlL".parse().unwrap();

    let bytes = rkyv::to_bytes(With::<SelfAddressingIdentifier, SAIDef>::cast(&value))?;
	dbg!(&bytes);
    let archived: &ArchivedSAIDef = rkyv::access(&bytes)?;

    let deserialized: SelfAddressingIdentifier =
        rkyv::deserialize(With::<ArchivedSAIDef, SAIDef>::cast(archived))?;

	// let des = rkyv_adapter::deserialize_element::<ArchivedSAIDef, SAIDef, SelfAddressingIdentifier>(&bytes);

    assert_eq!(value, deserialized);

    Ok(())
}