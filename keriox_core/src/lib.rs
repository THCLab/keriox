pub mod base;
pub mod database;
pub mod derivation;
pub mod error;
pub mod event;
pub mod event_message;
pub mod event_parsing;
pub mod keys;
pub mod prefix;
pub mod processor;
#[cfg(feature = "query")]
pub mod query;
pub mod signer;
pub mod state;

#[cfg(feature = "oobi")]
pub mod oobi;

pub mod prelude {
    pub use crate::base::{
        parse_event_stream, process_event, process_signed_oobi, process_signed_query,
    };
    pub use crate::database::sled::SledEventDatabase;
    pub use crate::processor::{
        basic_processor::BasicProcessor, event_storage::EventStorage, Processor,
    };
    pub use crate::query::ReplyType;
}
