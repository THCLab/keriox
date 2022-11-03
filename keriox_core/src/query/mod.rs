use crate::{
    derivation::self_addressing::SelfAddressing,
    error::Error,
    event::{EventMessage, SerializationFormats},
    event_message::{signed_event_message::Message, EventTypeTag, SaidEvent, Typeable},
};
use chrono::{DateTime, FixedOffset, SecondsFormat, Utc};
use serde::{Deserialize, Serialize, Serializer};

use self::{key_state_notice::KeyStateNotice, query_event::MailboxResponse};

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

    pub fn to_message(
        self,
        format: SerializationFormats,
        derivation: SelfAddressing,
    ) -> Result<EventMessage<SaidEvent<Timestamped<D>>>, Error> {
        SaidEvent::<Self>::to_message(self, format, derivation)
    }
}

impl<D: Serialize + Typeable> Typeable for Timestamped<D> {
    fn get_type(&self) -> EventTypeTag {
        self.data.get_type()
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum ReplyType {
    Ksn(KeyStateNotice),
    Kel(Vec<Message>),
    Mbx(MailboxResponse),
}

#[derive(Error, Debug, Serialize, Deserialize)]
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
