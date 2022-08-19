use crate::{
    event_message::signed_event_message::{Message, Op},
    oobi::{LocationScheme, Role},
    prefix::IdentifierPrefix,
};

pub mod default;

/// Transport trait allows customizing behavior of actors when it comes to making net requests.
/// Actors take a `dyn Transport` argument in `new` (dependency injection pattern).
/// This also allows providing a fake transport for tests.
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
