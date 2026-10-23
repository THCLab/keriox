use chrono::{DateTime, FixedOffset, SecondsFormat, Utc};
use serde::{Deserialize, Serialize, Serializer};

use super::{keri_version::KeriVersion, Typeable};
use crate::prefix::IdentifierPrefix;

pub type TimeStamp = DateTime<FixedOffset>;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Timestamped<D: Serialize> {
    /// The sender of a KERI 2.0 routed message (`qry`, `rpy`), written
    /// before `dt`. KERI 1.0 bodies have none.
    #[serde(rename = "i", default, skip_serializing_if = "Option::is_none")]
    pub sender: Option<IdentifierPrefix>,

    #[serde(rename = "dt", serialize_with = "serialize_timestamp")]
    pub timestamp: DateTime<FixedOffset>,

    #[serde(flatten)]
    pub data: D,
}

fn serialize_timestamp<S>(timestamp: &DateTime<FixedOffset>, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    s.serialize_str(&timestamp.to_rfc3339_opts(SecondsFormat::Micros, false))
}

impl<T: Serialize, D: Serialize + Typeable<TypeTag = T> + Clone> Timestamped<D> {
    pub fn new(data: D) -> Self {
        let timestamp: DateTime<FixedOffset> = Utc::now().into();
        Timestamped {
            sender: None,
            timestamp,
            data,
        }
    }

    /// The data sent by `sender` now, naming the sender in KERI 2.0 only.
    pub fn sent(data: D, sender: &IdentifierPrefix, version: KeriVersion) -> Self {
        Timestamped {
            sender: (version == KeriVersion::V2_0).then(|| sender.clone()),
            ..Timestamped::new(data)
        }
    }
}

impl<T: Serialize, D: Serialize + Typeable<TypeTag = T>> Typeable for Timestamped<D> {
    type TypeTag = T;
    fn get_type(&self) -> T {
        self.data.get_type()
    }
}
