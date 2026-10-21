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

/// Archived form of `SerializationInfo`. It keeps the layout written before
/// said 2.0, so stored events stay readable: the minor version is stored in
/// a byte and the genus version, which only V2 version strings carry, is not
/// stored.
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, PartialEq)]
#[rkyv(remote = SerializationInfo)]
pub(crate) struct SerializationInfoDef {
    pub protocol_code: String,
    pub major_version: u8,
    #[rkyv(getter = stored_minor_version)]
    pub minor_version: u8,
    pub size: usize,
    #[rkyv(getter = stored_kind)]
    pub kind: SerializationFormatsDef,
}

fn stored_minor_version(info: &SerializationInfo) -> u8 {
    // KERI 1.x minor versions are a single hex digit
    u8::try_from(info.minor_version).unwrap_or(u8::MAX)
}

fn stored_kind(info: &SerializationInfo) -> SerializationFormatsDef {
    match info.kind {
        SerializationFormats::JSON => SerializationFormatsDef::JSON,
        SerializationFormats::MGPK => SerializationFormatsDef::MGPK,
        SerializationFormats::CBOR => SerializationFormatsDef::CBOR,
        SerializationFormats::CESR => SerializationFormatsDef::CESR,
        other => unimplemented!("unsupported serialization format {other:?}"),
    }
}

impl From<SerializationInfoDef> for SerializationInfo {
    fn from(value: SerializationInfoDef) -> Self {
        SerializationInfo {
            protocol_code: value.protocol_code,
            major_version: value.major_version,
            minor_version: value.minor_version.into(),
            genus_version: None,
            size: value.size,
            kind: value.kind.into(),
        }
    }
}

/// Variants are only ever appended, as the archived discriminant is the
/// variant's position.
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, PartialEq)]
pub enum SerializationFormatsDef {
    JSON,
    MGPK,
    CBOR,
    CESR,
}

impl From<SerializationFormatsDef> for SerializationFormats {
    fn from(value: SerializationFormatsDef) -> Self {
        match value {
            SerializationFormatsDef::JSON => Self::JSON,
            SerializationFormatsDef::MGPK => Self::MGPK,
            SerializationFormatsDef::CBOR => Self::CBOR,
            SerializationFormatsDef::CESR => Self::CESR,
        }
    }
}
