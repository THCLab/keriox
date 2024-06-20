use std::error::Error;

use serde::Deserialize;

use crate::{
    actor::{error::ActorError, simple_controller::PossibleResponse},
    event_message::{
        cesr_adapter::ParseError,
        signed_event_message::{Message, Op},
    },
    oobi::{LocationScheme, Oobi, Role},
    prefix::IdentifierPrefix,
    query::query_event::SignedQueryMessage,
};

pub mod default;
// pub mod http;
pub mod test;

/// Transport trait allows customizing behavior of actors when it comes to making net requests.
/// Actors take a `dyn Transport` argument in `new` (dependency injection pattern).
/// This also allows providing a fake transport for tests.
#[async_trait::async_trait]
pub trait Transport<E = ActorError>
where
    E: for<'a> Deserialize<'a> + Error + Send + Sync + 'static,
{
    /// Send a message to other actor.
    /// This is used for sending notices, replies, and exchanges.
    /// To send query, prefer [`Transport::send_query`] method.
    async fn send_message(
        &self,
        loc: LocationScheme,
        msg: Message,
    ) -> Result<(), TransportError<E>>;

    #[cfg(feature = "query")]
    /// Send a query to other actor and return its response.
    async fn send_query(
        &self,
        loc: LocationScheme,
        qry: SignedQueryMessage,
    ) -> Result<PossibleResponse, TransportError<E>>;

    /// Request location scheme for id from other actor.
    /// Should use `get_eid_oobi` endpoint.
    /// Returns loc scheme replies.
    async fn request_loc_scheme(&self, loc: LocationScheme) -> Result<Vec<Op>, TransportError<E>>;

    /// Request end role for id from other actor.
    /// Should use `get_cid_oobi` endpoint.
    /// Returns end role replies.
    async fn request_end_role(
        &self,
        loc: LocationScheme,
        cid: IdentifierPrefix,
        role: Role,
        eid: IdentifierPrefix,
    ) -> Result<Vec<Message>, TransportError<E>>;

    /// Orders other actor to [`request_loc_scheme`](Transport::request_loc_scheme) or [`request_end_role`](Transport::request_end_role) and save result to its DB.
    /// Should use `resolve` endpoint.
    async fn resolve_oobi(&self, loc: LocationScheme, oobi: Oobi) -> Result<(), TransportError<E>>;
}

#[derive(Debug, thiserror::Error, serde::Serialize, serde::Deserialize)]
pub enum TransportError<E = ActorError> {
    #[error("network error: {0}")]
    NetworkError(String),
    #[error("Empty response")]
    EmptyResponse,
    #[error("Invalid response: {0}")]
    InvalidResponse(#[from] ParseError),
    #[error("Unknown error: {0}")]
    UnknownError(String),
    #[error("remote error: {0}")]
    RemoteError(E),
}
