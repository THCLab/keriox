use said::{sad::SerializationFormats, version::SerializationInfo};

#[derive(
    Debug,
    Clone,
    serde::Serialize,
    serde::Deserialize,
    Default,
    rkyv::Archive,
    rkyv::Serialize,
    rkyv::Deserialize,
    PartialEq,
)]
pub(crate) struct SerializationInfoValue {
    #[rkyv(with = SerializationInfoDef)]
    info: SerializationInfo,
}

#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, PartialEq)]
#[rkyv(remote = SerializationInfo)]
pub(crate) struct SerializationInfoDef {
    pub protocol_code: String,
    pub major_version: u8,
    pub minor_version: u8,
    pub size: usize,
    #[rkyv(with = SerializationFormatsDef)]
    pub kind: SerializationFormats,
}

impl From<SerializationInfoDef> for SerializationInfo {
    fn from(value: SerializationInfoDef) -> Self {
        SerializationInfo {
            protocol_code: value.protocol_code,
            major_version: value.major_version,
            minor_version: value.minor_version,
            size: value.size,
            kind: value.kind,
        }
    }
}

#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, PartialEq)]
#[rkyv(remote = SerializationFormats)]
pub enum SerializationFormatsDef {
    JSON,
    MGPK,
    CBOR,
}

impl From<SerializationFormatsDef> for SerializationFormats {
    fn from(value: SerializationFormatsDef) -> Self {
        match value {
            SerializationFormatsDef::JSON => Self::JSON,
            SerializationFormatsDef::MGPK => Self::MGPK,
            SerializationFormatsDef::CBOR => Self::CBOR,
        }
    }
}
