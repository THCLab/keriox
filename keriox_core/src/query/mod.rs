use crate::event_message::signed_event_message::Message;

use serde::{Deserialize, Serialize};

use self::key_state_notice::KeyStateNotice;

use thiserror::Error;

pub mod key_state_notice;
#[cfg(feature = "exchange")]
pub mod mailbox;
pub mod query_event;
pub mod reply_event;

#[derive(Clone, Debug, PartialEq)]
pub enum ReplyType {
    Ksn(KeyStateNotice),
    Kel(Vec<Message>),
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
