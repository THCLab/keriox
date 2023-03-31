use crate::error::Error;
use chrono::{DateTime, FixedOffset, SecondsFormat, Utc};
use keri::{
    event::sections::seal::EventSeal,
    event_message::{msg::KeriEvent, Typeable},
    prefix::IdentifierPrefix,
};
use said::{derivation::HashFunctionCode, SelfAddressingIdentifier};
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use serde_hex::{Compact, SerHex};
use serde_json::Value;
use version::serialization_info::SerializationFormats;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct TimestampedVCEvent {
    #[serde(flatten)]
    pub data: VCEvent,

    #[serde(
        rename = "dt",
        serialize_with = "timestamp_serialize",
        deserialize_with = "timestamp_deserialize"
    )]
    timestamp: DateTime<FixedOffset>,
}

impl Typeable for TimestampedVCEvent {
    type TypeTag = TelEventType;

    fn get_type(&self) -> Self::TypeTag {
        match self.data.event_type {
            VCEventType::Iss(_) => TelEventType::Iss,
            VCEventType::Rev(_) => TelEventType::Rev,
            VCEventType::Bis(_) => TelEventType::Bis,
            VCEventType::Brv(_) => TelEventType::Brv,
        }
    }
}

fn timestamp_serialize<S>(x: &DateTime<FixedOffset>, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    s.serialize_str(&x.to_rfc3339_opts(SecondsFormat::Micros, false))
}

fn timestamp_deserialize<'de, D>(deserializer: D) -> Result<DateTime<FixedOffset>, D::Error>
where
    D: de::Deserializer<'de>,
{
    let s: &str = de::Deserialize::deserialize(deserializer)?;
    // serde_json::from_str(s).map_err(de::Error::custom)
    let dt: DateTime<FixedOffset> = chrono::DateTime::parse_from_rfc3339(s).unwrap();
    Ok(dt)
}

impl TimestampedVCEvent {
    pub fn new(event: VCEvent) -> Self {
        Self {
            timestamp: Utc::now().into(),
            data: event,
        }
    }
}

impl From<TimestampedVCEvent> for VCEvent {
    fn from(item: TimestampedVCEvent) -> Self {
        item.data
    }
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "lowercase")]
pub enum TelEventType {
    Iss,
    Rev,
    Bis,
    Brv,
}

pub type VCEventMessage = KeriEvent<TimestampedVCEvent>;
impl Typeable for VCEvent {
    type TypeTag = TelEventType;
    fn get_type(&self) -> TelEventType {
        match self.event_type {
            VCEventType::Iss(_) => TelEventType::Iss,
            VCEventType::Rev(_) => TelEventType::Rev,
            VCEventType::Bis(_) => TelEventType::Bis,
            VCEventType::Brv(_) => TelEventType::Brv,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct VCEvent {
    #[serde(rename = "i")]
    ///  Verifiable Credential(VC) specific identifier will be a digest hash of the serialized contents of the VC
    pub prefix: IdentifierPrefix,

    #[serde(rename = "s", with = "SerHex::<Compact>")]
    pub sn: u64,

    #[serde(flatten)]
    pub event_type: VCEventType,
}

impl VCEvent {
    pub fn new(prefix: IdentifierPrefix, sn: u64, event_type: VCEventType) -> Self {
        Self {
            prefix,
            sn,
            event_type,
        }
    }
    pub fn to_message(
        self,
        format: SerializationFormats,
        derivation: HashFunctionCode,
    ) -> Result<VCEventMessage, Error> {
        let timestamped = TimestampedVCEvent::new(self);
        Ok(KeriEvent::new(format, derivation.into(), timestamped)?)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(untagged, rename_all = "lowercase")]
pub enum VCEventType {
    Iss(SimpleIssuance),
    Rev(SimpleRevocation),
    Bis(Issuance),
    Brv(Revocation),
}

impl<'de> Deserialize<'de> for VCEventType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        // Helper struct for adding tag to properly deserialize 't' field
        #[derive(Deserialize, Debug)]
        struct EventType {
            t: TelEventType,
        }

        let v = Value::deserialize(deserializer)?;
        let m = EventType::deserialize(&v).map_err(de::Error::custom)?;
        match m.t {
            TelEventType::Iss => Ok(VCEventType::Iss(
                SimpleIssuance::deserialize(&v).map_err(de::Error::custom)?,
            )),
            TelEventType::Rev => Ok(VCEventType::Rev(
                SimpleRevocation::deserialize(&v).map_err(de::Error::custom)?,
            )),
            TelEventType::Bis => Ok(VCEventType::Bis(
                Issuance::deserialize(&v).map_err(de::Error::custom)?,
            )),
            TelEventType::Brv => Ok(VCEventType::Brv(
                Revocation::deserialize(&v).map_err(de::Error::custom)?,
            )),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Issuance {
    #[serde(rename = "ii")]
    issuer_id: IdentifierPrefix,
    #[serde(rename = "ra")]
    registry_anchor: EventSeal,
}

impl Issuance {
    pub fn new(issuer_id: IdentifierPrefix, registry_anchor: EventSeal) -> Self {
        Self {
            issuer_id,
            registry_anchor,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SimpleIssuance {
    // registry identifier from management TEL
    #[serde(rename = "ri")]
    registry_id: IdentifierPrefix,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SimpleRevocation {
    #[serde(rename = "ri")]
    pub registry_id: IdentifierPrefix,
    #[serde(rename = "p")]
    pub prev_event_hash: SelfAddressingIdentifier,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Revocation {
    #[serde(rename = "p")]
    pub prev_event_hash: SelfAddressingIdentifier,
    // registry anchor to management TEL
    #[serde(rename = "ra")]
    pub registry_anchor: Option<EventSeal>,
}

#[test]
fn test_tel_event_serialization() -> Result<(), Error> {
    let iss_raw = r#"{"v":"KERI10JSON0000ed_","t":"iss","d":"EELqqdELW6CUVWfmsbt5sxfQfEOykyOWdUV12biBR4TH","i":"DAtNTPnDFBnmlO6J44LXCrzZTAmpe-82b7BmQGtL4QhM","s":"0","ri":"EE3Xv6CWwEMpW-99rhPD9IHFCR2LN5ienLVI8yG5faBw","dt":"2021-01-01T00:00:00.000000+00:00"}"#;
    let iss_ev: VCEventMessage = serde_json::from_str(&iss_raw).unwrap();

    assert_eq!(serde_json::to_string(&iss_ev).unwrap(), iss_raw);

    let rev_raw = r#"{"v":"KERI10JSON000120_","t":"rev","d":"EGtAthwVjf0O9qsSz0HR-C63DSEBhn3kRoxvmuRFECOQ","i":"DAtNTPnDFBnmlO6J44LXCrzZTAmpe-82b7BmQGtL4QhM","s":"1","ri":"EE3Xv6CWwEMpW-99rhPD9IHFCR2LN5ienLVI8yG5faBw","p":"EB2L3ycqK9645aEeQKP941xojSiuiHsw4Y6yTW-PmsBg","dt":"2021-01-01T00:00:00.000000+00:00"}"#;
    let rev_ev: VCEventMessage = serde_json::from_str(&rev_raw).unwrap();
    assert_eq!(serde_json::to_string(&rev_ev).unwrap(), rev_raw);

    let bis_raw = r#"{"v":"KERI10JSON000162_","t":"bis","d":"EF60WQClTmmJqbuHFHBAwmKiCT8RdE4rs6sIVC3s2_AH","i":"EC8Oej-3HAUpBY_kxzBK3B-0RV9j4dXw1H0NRKxJg7g-","s":"0","ii":"EKKJ0FoLxO1TYmyuprguKO7kJ7Hbn0m0Wuk5aMtSrMtY","ra":{"i":"EIZlA3TANi3p8vEu4VQMjPnY0sPFAag1ekIwyyR6lAsq","s":"0","d":"EFSL6HebpbWsxKxfdS4t6NbKTdO4hAUIAxvhmWVf3Z8o"},"dt":"2023-01-10T10:33:57.273969+00:00"}"#; //-GAB0AAAAAAAAAAAAAAAAAAAAAAQEJJR2nmwyYAfSVPzhzS6b5CMZAoTNZH3ULvaU6Z-i0d8"#;
    let bis_ev: VCEventMessage = serde_json::from_str(&bis_raw).unwrap();
    assert_eq!(serde_json::to_string(&bis_ev).unwrap(), bis_raw);

    let brv_raw = r#"{"v":"KERI10JSON00015f_","t":"brv","d":"EAIZZ8ujQQl4XGMh8XPzxokkzqrWh8M6FtxqkezbVtDu","i":"DAtNTPnDFBnmlO6J44LXCrzZTAmpe-82b7BmQGtL4QhM","s":"1","p":"EC2L3ycqK9645aEeQKP941xojSiuiHsw4Y6yTW-PmsBg","ra":{"i":"EE3Xv6CWwEMpW-99rhPD9IHFCR2LN5ienLVI8yG5faBw","s":"3","d":"EBpq06UecHwzy-K9FpNoRxCJp2wIGM9u2Edk-PLMZ1H4"},"dt":"2021-01-01T00:00:00.000000+00:00"}"#;
    let brv_ev: VCEventMessage = serde_json::from_str(&brv_raw).unwrap();
    assert_eq!(serde_json::to_string(&brv_ev).unwrap(), brv_raw);

    Ok(())
}
