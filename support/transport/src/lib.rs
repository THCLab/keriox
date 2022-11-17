use std::error::Error;

use keri::{
    actor::simple_controller::PossibleResponse,
    event_message::signed_event_message::{Message, Op},
    oobi::{LocationScheme, Role},
    prefix::IdentifierPrefix,
    query::query_event::SignedQuery,
};
use serde::Deserialize;

pub mod default;
pub mod test;

/// Transport trait allows customizing behavior of actors when it comes to making net requests.
/// Actors take a `dyn Transport` argument in `new` (dependency injection pattern).
/// This also allows providing a fake transport for tests.
#[async_trait::async_trait]
pub trait Transport<E>
where
    E: for<'a> Deserialize<'a> + Error + Send + Sync + 'static,
{
    /// Send a message to other actor.
    /// This is used for sending notices, replies, and exchanges.
    /// To send query, prefer [`Transport::send_query`] method.
    async fn send_message(&self, loc: LocationScheme, msg: Message) -> Result<(), TransportError<E>>;

    /// Send a query to other actor and return its response.
    async fn send_query(
        &self,
        loc: LocationScheme,
        qry: SignedQuery,
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
    ) -> Result<Vec<Op>, TransportError<E>>;

    // /// Orders other actor to [`request_loc_scheme`](Transport::request_loc_scheme) and save result to its DB.
    // /// Should use `resolve` endpoint.
    // async fn resolve_loc_scheme(&self, loc: LocationScheme) -> Result<(), TransportError>;

    // /// Orders other actor to [`request_end_role`](Transport::request_end_role) and save result to its DB.
    // /// Should use `resolve` endpoint.
    // async fn resolve_end_role(&self, role: EndRole) -> Result<(), TransportError>;
}

#[derive(Debug, thiserror::Error)]
pub enum TransportError<E> {
    #[error("network error")]
    NetworkError,
    #[error("invalid response")]
    InvalidResponse,
    #[error("remote error: {0}")]
    RemoteError(E),
}
