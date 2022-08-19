use crate::event_message::signed_event_message::Message;
use crate::event_message::signed_event_message::Op;
use crate::oobi::LocationScheme;
use crate::oobi::Role;
use crate::prefix::IdentifierPrefix;

pub mod default;

#[async_trait::async_trait]
pub trait Transport {
    /// Send a message to other actor and returns its response
    async fn send_message(
        &self,
        loc: LocationScheme,
        msg: Message,
    ) -> Result<Vec<Message>, TransportError>;

    /// Request location scheme for id from other actor.
    /// Should use `get_eid_oobi` endpoint.
    /// Returns loc scheme replies.
    async fn request_loc_scheme(&self, loc: LocationScheme) -> Result<Vec<Op>, TransportError>;

    /// Request end role for id from other actor.
    /// Should use `get_cid_oobi` endpoint.
    /// Returns end role replies.
    async fn request_end_role(
        &self,
        loc: LocationScheme,
        cid: IdentifierPrefix,
        role: Role,
        eid: IdentifierPrefix,
    ) -> Result<Vec<Op>, TransportError>;
}

#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    #[error("network error")]
    NetworkError,
    #[error("invalid response")]
    InvalidResponse,
    // TODO: add every possible keri error that could happen in the other actor
}
