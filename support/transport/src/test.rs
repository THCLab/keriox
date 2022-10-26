use std::collections::HashMap;

use keri::{
    actor::simple_controller::PossibleResponse,
    event_message::signed_event_message::{Message, Op},
    oobi::{LocationScheme, Role},
    prefix::IdentifierPrefix,
    query::query_event::SignedQuery,
};

use super::{Transport, TransportError};

#[async_trait::async_trait]
pub trait TestActor {
    async fn send_message(&self, msg: Message) -> Result<(), ActorError>;
    async fn send_query(&self, query: SignedQuery) -> Result<PossibleResponse, ActorError>;
    async fn request_loc_scheme(&self, eid: IdentifierPrefix) -> Result<Vec<Op>, ActorError>;
    async fn request_end_role(
        &self,
        cid: IdentifierPrefix,
        role: Role,
        eid: IdentifierPrefix,
    ) -> Result<Vec<Op>, ActorError>;
}

pub struct ActorError;

pub struct TestTransport {
    actors: HashMap<(url::Host, u16), Box<dyn TestActor + Send + Sync>>,
}

#[async_trait::async_trait]
impl Transport for TestTransport {
    async fn send_message(&self, loc: LocationScheme, msg: Message) -> Result<(), TransportError> {
        let (host, port) = match loc.url.origin() {
            url::Origin::Tuple(_scheme, host, port) => (host, port),
            _ => return Err(TransportError::NetworkError),
        };

        self.actors
            .get(&(host, port))
            .ok_or(TransportError::NetworkError)?
            .send_message(msg)
            .await
            .map_err(|_| TransportError::InvalidResponse)?;

        Ok(())
    }

    async fn send_query(
        &self,
        loc: LocationScheme,
        qry: SignedQuery,
    ) -> Result<PossibleResponse, TransportError> {
        let (host, port) = match loc.url.origin() {
            url::Origin::Tuple(_scheme, host, port) => (host, port),
            _ => return Err(TransportError::NetworkError),
        };

        let resp = self
            .actors
            .get(&(host, port))
            .ok_or(TransportError::NetworkError)?
            .send_query(qry)
            .await
            .map_err(|_| TransportError::NetworkError)?;

        Ok(resp)
    }

    async fn request_loc_scheme(&self, loc: LocationScheme) -> Result<Vec<Op>, TransportError> {
        let (host, port) = match loc.url.origin() {
            url::Origin::Tuple(_scheme, host, port) => (host, port),
            _ => return Err(TransportError::NetworkError),
        };

        let ops = self
            .actors
            .get(&(host, port))
            .ok_or(TransportError::NetworkError)?
            .request_loc_scheme(loc.eid)
            .await
            .map_err(|_| TransportError::NetworkError)?;

        Ok(ops)
    }

    async fn request_end_role(
        &self,
        loc: LocationScheme,
        cid: IdentifierPrefix,
        role: Role,
        eid: IdentifierPrefix,
    ) -> Result<Vec<Op>, TransportError> {
        let (host, port) = match loc.url.origin() {
            url::Origin::Tuple(_scheme, host, port) => (host, port),
            _ => return Err(TransportError::NetworkError),
        };

        let ops = self
            .actors
            .get(&(host, port))
            .ok_or(TransportError::NetworkError)?
            .request_end_role(cid, role, eid)
            .await
            .map_err(|_| TransportError::NetworkError)?;

        Ok(ops)
    }
}
