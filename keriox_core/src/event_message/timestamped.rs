use chrono::{DateTime, FixedOffset, SecondsFormat, Utc};
use serde::{Deserialize, Serialize, Serializer};

use super::Typeable;

pub type TimeStamp = DateTime<FixedOffset>;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Timestamped<D: Serialize> {
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
        Timestamped { timestamp, data }
    }
}

impl<T: Serialize, D: Serialize + Typeable<TypeTag = T>> Typeable for Timestamped<D> {
    type TypeTag = T;
    fn get_type(&self) -> T {
        self.data.get_type()
    }
}
