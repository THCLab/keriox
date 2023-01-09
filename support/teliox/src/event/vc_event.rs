use crate::error::Error;
use chrono::{DateTime, FixedOffset, Local, SecondsFormat};
use keri::{
    event::{sections::seal::EventSeal, SerializationFormats},
    event_message::serialization_info::SerializationInfo,
    prefix::{IdentifierPrefix},
    sai::SelfAddressingPrefix,
};
use serde::{de, Deserialize, Serialize, Serializer};
use serde_hex::{Compact, SerHex};

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct TimestampedVCEvent {
    #[serde(flatten)]
    pub event: VCEvent,

    #[serde(
        rename = "dt",
        serialize_with = "timestamp_serialize",
        deserialize_with = "timestamp_deserialize"
    )]
    timestamp: DateTime<Local>,
}

fn timestamp_serialize<S>(x: &DateTime<Local>, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let dt: DateTime<FixedOffset> = DateTime::from(x.to_owned());
    s.serialize_str(&dt.to_rfc3339_opts(SecondsFormat::Secs, false))
}

fn timestamp_deserialize<'de, D>(deserializer: D) -> Result<DateTime<Local>, D::Error>
where
    D: de::Deserializer<'de>,
{
    let s: &str = de::Deserialize::deserialize(deserializer)?;
    // serde_json::from_str(s).map_err(de::Error::custom)
    let dt: DateTime<Local> = DateTime::from(chrono::DateTime::parse_from_rfc3339(s).unwrap());
    Ok(dt)
}

impl TimestampedVCEvent {
    pub fn new(event: VCEvent) -> Self {
        Self {
            timestamp: Local::now(),
            event,
        }
    }
}

impl From<TimestampedVCEvent> for VCEvent {
    fn from(item: TimestampedVCEvent) -> Self {
        item.event
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct VCEvent {
    #[serde(rename = "v")]
    pub serialization_info: SerializationInfo,

    #[serde(rename = "i")]
    // VC specific identifier will be a digest hash of the serialized contents of the VC
    pub prefix: IdentifierPrefix,

    #[serde(rename = "s", with = "SerHex::<Compact>")]
    pub sn: u64,

    #[serde(flatten)]
    pub event_type: VCEventType,
}

impl VCEvent {
    pub fn new(
        prefix: IdentifierPrefix,
        sn: u64,
        event_type: VCEventType,
        format: SerializationFormats,
    ) -> Result<Self, Error> {
        let size = Self {
            serialization_info: SerializationInfo::new(format, 0),
            prefix: prefix.clone(),
            sn,
            event_type: event_type.clone(),
        }
        .serialize()?
        .len();
        let serialization_info = SerializationInfo::new(format, size);
        Ok(Self {
            serialization_info,
            prefix,
            sn,
            event_type,
        })
    }

    pub fn serialize(&self) -> Result<Vec<u8>, Error> {
        self.serialization_info
            .kind
            .encode(self)
            .map_err(|e| Error::KeriError(e))
    }
}

// #[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
// pub struct Identifier {}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "lowercase")]
pub enum VCEventType {
    Iss(SimpleIssuance),
    Rev(SimpleRevocation),
    Bis(Issuance),
    Brv(Revocation),
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Issuance {
    #[serde(rename = "ra")]
    registry_anchor: EventSeal,
}

impl Issuance {
    pub fn new(registry_anchor: EventSeal) -> Self {
        Self { registry_anchor }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SimpleIssuance {
    // registry identifier from management TEL
    #[serde(rename = "ri")]
    registry_id: IdentifierPrefix,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SimpleRevocation {
    #[serde(rename = "p")]
    pub prev_event_hash: SelfAddressingPrefix,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Revocation {
    #[serde(rename = "p")]
    pub prev_event_hash: SelfAddressingPrefix,
    // registry anchor to management TEL
    #[serde(rename = "ra")]
    pub registry_anchor: Option<EventSeal>,
}

#[test]
fn test_tel_event_serialization() -> Result<(), Error> {
    let iss_raw = r#"{"v":"KERI11JSON0000b3_","i":"Ezpq06UecHwzy-K9FpNoRxCJp2wIGM9u2Edk-PLMZ1H4","s":"0","t":"iss","ri":"EE3Xv6CWwEMpW-99rhPD9IHFCR2LN5ienLVI8yG5faBw","dt":"2021-01-01T00:00:00+00:00"}"#;
    let iss_ev: TimestampedVCEvent = serde_json::from_str(&iss_raw).unwrap();

    assert_eq!(serde_json::to_string(&iss_ev).unwrap(), iss_raw);

    let rev_raw = r#"{"v":"KERI10JSON0000e6_","i":"DntNTPnDFBnmlO6J44LXCrzZTAmpe-82b7BmQGtL4QhM","s":"1","t":"rev","p":"EY2L3ycqK9645aEeQKP941xojSiuiHsw4Y6yTW-PmsBg","dt":"2021-01-01T00:00:00+00:00"}"#;
    let rev_ev: TimestampedVCEvent = serde_json::from_str(&rev_raw).unwrap();
    assert_eq!(serde_json::to_string(&rev_ev).unwrap(), rev_raw);

    let bis_raw = r#"{"v":"KERI10JSON000126_","i":"DntNTPnDFBnmlO6J44LXCrzZTAmpe-82b7BmQGtL4QhM","s":"0","t":"bis","ra":{"i":"EE3Xv6CWwEMpW-99rhPD9IHFCR2LN5ienLVI8yG5faBw","s":"3","d":"Ezpq06UecHwzy-K9FpNoRxCJp2wIGM9u2Edk-PLMZ1H4"},"dt":"2021-01-01T00:00:00+00:00"}"#;
    let bis_ev: TimestampedVCEvent = serde_json::from_str(&bis_raw).unwrap();
    assert_eq!(serde_json::to_string(&bis_ev).unwrap(), bis_raw);

    let brv_raw = r#"{"v":"KERI10JSON000125_","i":"DntNTPnDFBnmlO6J44LXCrzZTAmpe-82b7BmQGtL4QhM","s":"1","t":"brv","p":"EY2L3ycqK9645aEeQKP941xojSiuiHsw4Y6yTW-PmsBg","ra":{"i":"EE3Xv6CWwEMpW-99rhPD9IHFCR2LN5ienLVI8yG5faBw","s":"3","d":"Ezpq06UecHwzy-K9FpNoRxCJp2wIGM9u2Edk-PLMZ1H4"},"dt":"2021-01-01T00:00:00+00:00"}"#;
    let brv_ev: TimestampedVCEvent = serde_json::from_str(&brv_raw).unwrap();
    assert_eq!(serde_json::to_string(&brv_ev).unwrap(), brv_raw);

    Ok(())
}
