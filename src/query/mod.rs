use crate::{
    derivation::self_addressing::SelfAddressing,
    error::Error,
    event::{EventMessage, SerializationFormats},
    event_message::{EventTypeTag, SaidEvent, Typeable},
};
use chrono::{DateTime, FixedOffset, SecondsFormat, Utc};
use serde::{Deserialize, Serialize, Serializer};

use self::{reply_event::SignedReply};

use thiserror::Error;

pub mod key_state_notice;
pub mod query_event;
pub mod reply_event;

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

impl<D: Serialize + Typeable + Clone> Timestamped<D> {
    pub fn new(data: D) -> Self {
        let timestamp: DateTime<FixedOffset> = Utc::now().into();
        Timestamped { timestamp, data }
    }

    fn to_message(
        self,
        format: SerializationFormats,
        derivation: &SelfAddressing,
    ) -> Result<EventMessage<SaidEvent<Timestamped<D>>>, Error> {
        SaidEvent::<Self>::to_message(self, format, derivation)
    }
}

impl<D: Serialize + Typeable> Typeable for Timestamped<D> {
    fn get_type(&self) -> EventTypeTag {
        self.data.get_type()
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
// #[serde(tag = "r", content = "a")]
pub enum QueryRoute {
    #[serde(rename = "log")]
    Log,
    #[serde(rename = "ksn")]
    Ksn,
}

#[derive(Debug)]
pub enum ReplyType {
    Rep(SignedReply),
    Kel(Vec<u8>),
}

#[derive(Error, Debug)]
pub enum QueryError {
    #[error("Got stale key state notice")]
    StaleKsn,
    #[error("Got stale reply message")]
    StaleRpy,
    #[error("No previous reply in database")]
    NoSavedReply,
    #[error("Error: {0}")]
    Error(String),
}
