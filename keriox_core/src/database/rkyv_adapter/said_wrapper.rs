use said::{
    derivation::{HashFunction, HashFunctionCode},
    SelfAddressingIdentifier,
};

use rkyv::{Archive, Deserialize, Serialize};

#[derive(
    Debug, Clone, Default, Eq, Hash, Archive, rkyv::Serialize, rkyv::Deserialize, PartialEq,
)]
#[rkyv(derive(Debug))]
pub struct SaidValue {
    #[rkyv(with = SAIDef)]
    pub said: SelfAddressingIdentifier,
}

impl From<SelfAddressingIdentifier> for SaidValue {
    fn from(value: SelfAddressingIdentifier) -> Self {
        Self { said: value }
    }
}

impl From<SaidValue> for SelfAddressingIdentifier {
    fn from(value: SaidValue) -> Self {
        value.said
    }
}

impl serde::Serialize for SaidValue {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.said.serialize(serializer)
    }
}

impl<'de> serde::Deserialize<'de> for SaidValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        SelfAddressingIdentifier::deserialize(deserializer).map(|said| SaidValue { said })
    }
}

#[derive(Archive, Serialize, Deserialize)]
#[rkyv(remote = SelfAddressingIdentifier)]
#[rkyv(derive(Debug))]
pub(crate) struct SAIDef {
    #[rkyv(with = HashFunctionDef)]
    pub derivation: HashFunction,
    pub digest: Vec<u8>,
}

impl From<SAIDef> for SelfAddressingIdentifier {
    fn from(value: SAIDef) -> Self {
        Self::new(value.derivation, value.digest)
    }
}

#[derive(Archive, Serialize, Deserialize, PartialEq)]
#[rkyv(remote = HashFunction)]
#[rkyv(derive(Debug))]
struct HashFunctionDef {
    #[rkyv(getter = HashFunctionDef::get_code, with = HashFunctionCodeDef)]
    pub f: HashFunctionCode,
}

impl HashFunctionDef {
    fn get_code(foo: &HashFunction) -> HashFunctionCode {
        foo.into()
    }
}

impl From<HashFunctionDef> for HashFunction {
    fn from(value: HashFunctionDef) -> Self {
        value.f.into()
    }
}

#[derive(Archive, Serialize, Deserialize, PartialEq)]
#[rkyv(remote = HashFunctionCode)]
#[rkyv(compare(PartialEq), derive(Debug))]
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

#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
// #[rkyv(
//     compare(PartialEq),
//     derive(Debug),
// )]
struct OptionalSaid {
    value: SaidValue,
}

#[test]
fn test_rkyv_said_serialization() -> Result<(), rkyv::rancor::Failure> {
    use rkyv::with::With;
    let value: SelfAddressingIdentifier = "EJe_sKQb1otKrz6COIL8VFvBv3DEFvtKaVFGn1vm0IlL"
        .parse()
        .unwrap();

    let bytes = rkyv::to_bytes(With::<SelfAddressingIdentifier, SAIDef>::cast(&value))?;
    dbg!(&bytes);
    let archived: &ArchivedSAIDef = rkyv::access(&bytes)?;

    let deserialized: SelfAddressingIdentifier =
        rkyv::deserialize(With::<ArchivedSAIDef, SAIDef>::cast(archived))?;

    // let des = rkyv_adapter::deserialize_element::<ArchivedSAIDef, SAIDef, SelfAddressingIdentifier>(&bytes);

    assert_eq!(value, deserialized);

    Ok(())
}
