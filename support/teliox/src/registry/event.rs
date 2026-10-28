//! The messages of an ACDC 2.0 state registry (TEL): registry inception
//! `rip`, blindable update `bup` and update `upd` (ACDC specification,
//! "Transaction event logs (TELs) as ACDC state registries"). They are ACDC
//! protocol messages, not KERI ones, and carry no signatures: each is
//! committed to by a seal in the Issuer's KEL.

use chrono::{DateTime, FixedOffset, Utc};
use keri_core::{
    event_message::{msg::TypedEvent, Typeable},
    prefix::IdentifierPrefix,
};
use said::{
    derivation::{HashFunction, HashFunctionCode},
    version::{format::SerializationFormats, SerializationInfo},
    SelfAddressingIdentifier,
};
use serde::{Deserialize, Serialize};

use super::RegistryError;

/// The message type, `t`, of a registry event.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum RegistryIlk {
    Rip,
    Bup,
    Upd,
}

/// A registry event: `v`, `t` and `d`, then the fields of its type.
pub type RegistryEvent<D> = TypedEvent<RegistryIlk, D>;

/// `rip` after `d`: `[u, i, n, dt]`.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Inception {
    /// The salty nonce that makes the registry's SAID unguessable.
    #[serde(rename = "u")]
    pub nonce: String,
    #[serde(rename = "i")]
    pub issuer: IdentifierPrefix,
    #[serde(rename = "n", with = "hex_number")]
    pub sn: u64,
    #[serde(rename = "dt", with = "micros")]
    pub timestamp: DateTime<FixedOffset>,
}

/// `bup` after `d`: `[rd, n, p, dt, b]`.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct BlindableUpdate {
    #[serde(rename = "rd")]
    pub registry: SelfAddressingIdentifier,
    #[serde(rename = "n", with = "hex_number")]
    pub sn: u64,
    #[serde(rename = "p")]
    pub prior: SelfAddressingIdentifier,
    #[serde(rename = "dt", with = "micros")]
    pub timestamp: DateTime<FixedOffset>,
    /// The BLID of the blinded state block.
    #[serde(rename = "b")]
    pub blid: SelfAddressingIdentifier,
}

/// `upd` after `d`: `[rd, n, p, dt, td, ts]`. The specification's field list
/// names the transaction ACDC SAID `ta` and its description `td`; keripy
/// writes `td`, as this does.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Update {
    #[serde(rename = "rd")]
    pub registry: SelfAddressingIdentifier,
    #[serde(rename = "n", with = "hex_number")]
    pub sn: u64,
    #[serde(rename = "p")]
    pub prior: SelfAddressingIdentifier,
    #[serde(rename = "dt", with = "micros")]
    pub timestamp: DateTime<FixedOffset>,
    #[serde(rename = "td")]
    pub acdc: SelfAddressingIdentifier,
    #[serde(rename = "ts")]
    pub state: String,
}

impl Typeable for Inception {
    type TypeTag = RegistryIlk;
    fn get_type(&self) -> RegistryIlk {
        RegistryIlk::Rip
    }
}

impl Typeable for BlindableUpdate {
    type TypeTag = RegistryIlk;
    fn get_type(&self) -> RegistryIlk {
        RegistryIlk::Bup
    }
}

impl Typeable for Update {
    type TypeTag = RegistryIlk;
    fn get_type(&self) -> RegistryIlk {
        RegistryIlk::Upd
    }
}

/// The version string of an ACDC 2.0 message of `kind`.
fn acdc_version(kind: SerializationFormats) -> SerializationInfo {
    let mut info = SerializationInfo::new_empty("ACDC".to_string(), 2, 0, kind);
    info.genus_version = Some((2, 0));
    info
}

/// A registry event of `body`, in JSON, with its SAID computed.
pub(crate) fn build<D>(body: D) -> RegistryEvent<D>
where
    D: Serialize + Clone + Typeable<TypeTag = RegistryIlk>,
{
    TypedEvent::with_serialization_info(
        acdc_version(SerializationFormats::JSON),
        HashFunction::from(HashFunctionCode::Blake3_256),
        body,
    )
}

/// The time now, as registry events carry it.
pub(crate) fn now() -> DateTime<FixedOffset> {
    Utc::now().into()
}

/// Any registry event.
#[derive(Debug, Clone, PartialEq)]
pub enum RegistryMessage {
    Inception(RegistryEvent<Inception>),
    Blindable(RegistryEvent<BlindableUpdate>),
    Update(RegistryEvent<Update>),
}

impl RegistryMessage {
    /// Reads a registry event body, as the type its `t` names. The body must
    /// be an ACDC 2.x message, its version string must give its kind and
    /// size, it must be written canonically, and its SAID must verify.
    pub fn parse(raw: &[u8]) -> Result<Self, RegistryError> {
        let kind = body_kind(raw)?;
        #[derive(Deserialize)]
        struct Ilk {
            t: RegistryIlk,
        }
        let ilk = decode::<Ilk>(raw, kind)?.t;
        let message = match ilk {
            RegistryIlk::Rip => RegistryMessage::Inception(decode(raw, kind)?),
            RegistryIlk::Bup => RegistryMessage::Blindable(decode(raw, kind)?),
            RegistryIlk::Upd => RegistryMessage::Update(decode(raw, kind)?),
        };
        let info = message.serialization_info();
        if info.protocol_code != "ACDC" || info.major_version != 2 {
            return Err(RegistryError::Format(format!(
                "a registry event is an ACDC 2.x message, not {} {}.{}",
                info.protocol_code, info.major_version, info.minor_version
            )));
        }
        if info.kind != kind {
            return Err(RegistryError::Format(format!(
                "version string names a {:?} body, the body is {kind:?}",
                info.kind
            )));
        }
        if info.size != raw.len() {
            return Err(RegistryError::Format(format!(
                "version string gives size {}, the body has {} bytes",
                info.size,
                raw.len()
            )));
        }
        if message.encode()? != raw {
            return Err(RegistryError::Format(
                "body differs from its canonical serialization".into(),
            ));
        }
        let verified = match &message {
            RegistryMessage::Inception(event) => event.check_digest(),
            RegistryMessage::Blindable(event) => event.check_digest(),
            RegistryMessage::Update(event) => event.check_digest(),
        };
        verified.map_err(|e| RegistryError::Format(format!("SAID: {e}")))?;
        Ok(message)
    }

    pub fn encode(&self) -> Result<Vec<u8>, RegistryError> {
        match self {
            RegistryMessage::Inception(event) => event.encode(),
            RegistryMessage::Blindable(event) => event.encode(),
            RegistryMessage::Update(event) => event.encode(),
        }
        .map_err(|e| RegistryError::Format(e.to_string()))
    }

    fn serialization_info(&self) -> &SerializationInfo {
        match self {
            RegistryMessage::Inception(event) => &event.serialization_info,
            RegistryMessage::Blindable(event) => &event.serialization_info,
            RegistryMessage::Update(event) => &event.serialization_info,
        }
    }

    /// The event's SAID.
    pub fn said(&self) -> Result<SelfAddressingIdentifier, RegistryError> {
        match self {
            RegistryMessage::Inception(event) => event.digest(),
            RegistryMessage::Blindable(event) => event.digest(),
            RegistryMessage::Update(event) => event.digest(),
        }
        .map_err(|e| RegistryError::Format(e.to_string()))
    }

    /// The SAID of the registry the event belongs to: its own for a `rip`.
    pub fn registry(&self) -> Result<SelfAddressingIdentifier, RegistryError> {
        match self {
            RegistryMessage::Inception(_) => self.said(),
            RegistryMessage::Blindable(event) => Ok(event.data.registry.clone()),
            RegistryMessage::Update(event) => Ok(event.data.registry.clone()),
        }
    }

    /// The event's sequence number in its registry.
    pub fn sn(&self) -> u64 {
        match self {
            RegistryMessage::Inception(event) => event.data.sn,
            RegistryMessage::Blindable(event) => event.data.sn,
            RegistryMessage::Update(event) => event.data.sn,
        }
    }

    /// The SAID of the prior event; none for a `rip`.
    pub fn prior(&self) -> Option<&SelfAddressingIdentifier> {
        match self {
            RegistryMessage::Inception(_) => None,
            RegistryMessage::Blindable(event) => Some(&event.data.prior),
            RegistryMessage::Update(event) => Some(&event.data.prior),
        }
    }
}

fn body_kind(raw: &[u8]) -> Result<SerializationFormats, RegistryError> {
    match raw.first() {
        Some(b'{') => Ok(SerializationFormats::JSON),
        Some(0xa0..=0xbf) => Ok(SerializationFormats::CBOR),
        Some(0x80..=0x8f) => Ok(SerializationFormats::MGPK),
        _ => Err(RegistryError::Format("not a JSON, CBOR or MGPK body".into())),
    }
}

fn decode<T: serde::de::DeserializeOwned>(
    raw: &[u8],
    kind: SerializationFormats,
) -> Result<T, RegistryError> {
    match kind {
        SerializationFormats::JSON => serde_json::from_slice(raw).map_err(|e| e.to_string()),
        SerializationFormats::CBOR => serde_cbor::from_slice(raw).map_err(|e| e.to_string()),
        SerializationFormats::MGPK => rmp_serde::from_slice(raw).map_err(|e| e.to_string()),
        _ => Err("unsupported body".to_string()),
    }
    .map_err(RegistryError::Format)
}

/// Sequence numbers as lowercase hex without leading zeros.
mod hex_number {
    use serde::{de, Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(n: &u64, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&format!("{n:x}"))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<u64, D::Error> {
        let hex = String::deserialize(d)?;
        if hex.is_empty() || (hex.len() > 1 && hex.starts_with('0')) || hex != hex.to_lowercase()
        {
            return Err(de::Error::custom(format!("{hex:?} is not a sequence number")));
        }
        u64::from_str_radix(&hex, 16).map_err(de::Error::custom)
    }
}

/// Date-times with microseconds and a numeric UTC offset.
mod micros {
    use chrono::{DateTime, FixedOffset, SecondsFormat};
    use serde::{de, Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(t: &DateTime<FixedOffset>, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&t.to_rfc3339_opts(SecondsFormat::Micros, false))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<DateTime<FixedOffset>, D::Error> {
        let text = String::deserialize(d)?;
        DateTime::parse_from_rfc3339(&text).map_err(de::Error::custom)
    }
}
