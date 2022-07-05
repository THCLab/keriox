use std::{cmp::Ordering, time::Duration};

use chrono::{DateTime, Local};
use serde::{Deserialize, Serialize};

use crate::{
    error::Error,
    event_message::signed_event_message::{
        SignedEventMessage, SignedNontransferableReceipt, SignedTransferableReceipt,
    },
};

#[derive(Serialize, Deserialize, Debug)]
pub struct Timestamped<M> {
    pub timestamp: DateTime<Local>,
    pub signed_event_message: M,
}

impl<M> Timestamped<M> {
    pub fn new(event: M) -> Self {
        Self {
            timestamp: Local::now(),
            signed_event_message: event,
        }
    }

    pub fn is_stale(&self, duration: Duration) -> Result<bool, Error> {
        Ok(Local::now() - self.timestamp
            >= chrono::Duration::from_std(duration)
                .map_err(|_e| Error::SemanticError("Improper duration".into()))?)
    }
}

impl From<Timestamped<SignedEventMessage>> for SignedEventMessage {
    fn from(event: Timestamped<SignedEventMessage>) -> SignedEventMessage {
        event.signed_event_message
    }
}

impl From<Timestamped<SignedNontransferableReceipt>> for SignedNontransferableReceipt {
    fn from(event: Timestamped<SignedNontransferableReceipt>) -> SignedNontransferableReceipt {
        event.signed_event_message
    }
}

impl From<Timestamped<SignedTransferableReceipt>> for SignedTransferableReceipt {
    fn from(event: Timestamped<SignedTransferableReceipt>) -> SignedTransferableReceipt {
        event.signed_event_message
    }
}

impl<M> From<M> for Timestamped<M> {
    fn from(event: M) -> Timestamped<M> {
        Timestamped::new(event)
    }
}

impl<M: Clone> From<&M> for Timestamped<M> {
    fn from(event: &M) -> Timestamped<M> {
        Timestamped::new(event.clone())
    }
}

impl<M: PartialEq> PartialEq for Timestamped<M> {
    fn eq(&self, other: &Self) -> bool {
        self.signed_event_message == other.signed_event_message
    }
}

impl PartialOrd for Timestamped<SignedEventMessage> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(
            match self.signed_event_message.event_message.event.get_sn()
                == other.signed_event_message.event_message.event.get_sn()
            {
                true => Ordering::Equal,
                false => {
                    match self.signed_event_message.event_message.event.get_sn()
                        > other.signed_event_message.event_message.event.get_sn()
                    {
                        true => Ordering::Greater,
                        false => Ordering::Less,
                    }
                }
            },
        )
    }
}

impl Ord for Timestamped<SignedEventMessage> {
    fn cmp(&self, other: &Self) -> Ordering {
        match self.signed_event_message.event_message.event.get_sn()
            == other.signed_event_message.event_message.event.get_sn()
        {
            true => Ordering::Equal,
            false => match self.signed_event_message.event_message.event.get_sn()
                > other.signed_event_message.event_message.event.get_sn()
            {
                true => Ordering::Greater,
                false => Ordering::Less,
            },
        }
    }
}

impl Eq for Timestamped<SignedEventMessage> {}

pub type TimestampedSignedEventMessage = Timestamped<SignedEventMessage>;
