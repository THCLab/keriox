use std::sync::Arc;

use futures::future::join_all;
use keri_core::{
    actor::{error::ActorError, parse_event_stream, possible_response::PossibleResponse},
    database::{EscrowCreator, EventDatabase},
    event_message::signed_event_message::{Message, Notice, Op, SignedEventMessage},
    oobi::{EndRole, LocationScheme, Oobi},
    oobi_manager::storage::OobiStorageBackend,
    prefix::{BasicPrefix, IdentifierPrefix},
    query::query_event::{SignedKelQuery, SignedQueryMessage},
    transport::{Transport, TransportError},
};
use teliox::registry::RegistryStore;

use crate::{
    error::ControllerError,
    identifier::mechanics::MechanicsError,
    known_events::{KnownEvents, OobiRetrieveError},
};

#[derive(Debug, thiserror::Error)]
pub enum SendingError {
    #[error("Actor doesn't have identifier {missing} oobi")]
    WatcherDosntHaveOobi { missing: IdentifierPrefix },

    #[error("Actor internal error: {0}")]
    ActorInternalError(#[from] ActorError),

    #[error("Transport error: {0}")]
    TransportError(keri_core::transport::TransportError),

    #[error("Http request error: {0}")]
    HTTPError(#[from] reqwest::Error),

    #[error(transparent)]
    OobiError(#[from] OobiRetrieveError),

    #[error("Invalid url: {0}")]
    InvalidUrl(#[from] url::ParseError),

    #[error("The location of {eid} is nullified")]
    NullifiedLocation { eid: IdentifierPrefix },

    #[error("The query names no server to send it to")]
    MissingRecipient,
}

impl From<TransportError> for SendingError {
    fn from(value: TransportError) -> Self {
        match value {
            TransportError::RemoteError(ActorError::NoIdentState { prefix }) => {
                Self::WatcherDosntHaveOobi { missing: prefix }
            }
            TransportError::RemoteError(internal_error) => Self::ActorInternalError(internal_error),
            e => Self::TransportError(e),
        }
    }
}

pub struct Communication<D, T, S>
where
    D: EventDatabase + EscrowCreator + 'static,
    T: RegistryStore + 'static,
    S: OobiStorageBackend,
{
    pub events: Arc<KnownEvents<D, T, S>>,
    pub transport: Box<dyn Transport + Send + Sync>,
}

impl<D, T, S> Communication<D, T, S>
where
    D: EventDatabase + EscrowCreator + Send + Sync + 'static,
    T: RegistryStore + Send + Sync + 'static,
    S: OobiStorageBackend,
{
    pub fn new(
        known_events: Arc<KnownEvents<D, T, S>>,
        transport: Box<dyn Transport<ActorError> + Send + Sync>,
    ) -> Self {
        Communication {
            events: known_events,
            transport,
        }
    }

    /// Make http request to get identifier's endpoints information.
    pub async fn resolve_loc_schema(&self, lc: &LocationScheme) -> Result<(), MechanicsError> {
        let oobis = self.transport.request_loc_scheme(lc.clone()).await?;
        for oobi in oobis {
            self.events.save(&Message::Op(oobi))?;
        }
        Ok(())
    }

    /// Make http request to get identifier's endpoints information.
    pub async fn resolve_end_role(&self, er: &EndRole) -> Result<(), MechanicsError> {
        let EndRole { cid, role, eid } = er.clone();
        let loc = self
            .events
            .find_http_location(&eid)
            .map_err(SendingError::OobiError)?;
        let response = self.transport.request_end_role(loc, cid, role, eid).await?;

        let msgs = parse_event_stream(response.as_ref()).map_err(|e| {
            MechanicsError::OtherError(format!(
                "Can't parse response while oobi resolving: {}",
                e.to_string()
            ))
        })?;
        for msg in msgs {
            // TODO This ignore signatures. Add verification.
            if let Message::Op(Op::Reply(signed_oobi)) = msg {
                self.events.save_oobi(&signed_oobi)?;
            } else {
                self.events.save(&msg)?;
            }
        }
        Ok(())
    }

    /// Make http request to get identifier's endpoints information.
    pub async fn resolve_oobi(&self, oobi: &Oobi) -> Result<(), MechanicsError> {
        match oobi {
            Oobi::Location(loc) => self.resolve_loc_schema(loc).await,
            Oobi::EndRole(er) => self.resolve_end_role(er).await,
        }
    }

    pub async fn send_message_to(
        &self,
        id: IdentifierPrefix,
        msg: Message,
    ) -> Result<(), SendingError> {
        let loc = self.events.find_http_location(&id)?;
        self.transport.send_message(loc, msg).await?;
        Ok(())
    }

    pub async fn send_query_to(
        &self,
        id: &IdentifierPrefix,
        query: SignedKelQuery,
    ) -> Result<PossibleResponse, SendingError> {
        let loc = self.events.find_http_location(id)?;
        Ok(self
            .transport
            .send_query(loc, SignedQueryMessage::KelQuery(query))
            .await?)
    }

    async fn send_oobi_to(&self, id: &IdentifierPrefix, oobi: Oobi) -> Result<(), SendingError> {
        let loc = self.events.find_http_location(id)?;
        self.transport.resolve_oobi(loc, oobi).await?;
        Ok(())
    }

    /// Publish key event to witnesses
    ///
    ///  1. send it to all witnesses
    ///  2. collect witness receipts and process them
    ///  3. get processed receipts from db and send it to all witnesses
    pub async fn publish(
        &self,
        witness_prefixes: Vec<BasicPrefix>,
        message: &SignedEventMessage,
    ) -> Result<(), MechanicsError> {
        // Get processed receipts from database to send all of them to witnesses. It
        // will return one receipt with all witness signatures as one attachment,
        // not three separate receipts as in `collected_receipts`.
        let (prefix, sn, digest) = (
            message.event_message.data.get_prefix(),
            message.event_message.data.get_sn(),
            message.event_message.digest(),
        );
        let rcts_from_db = self
            .events
            .find_receipt(&prefix, sn, &digest?)?
            .map(|rct| Message::Notice(Notice::NontransferableRct(rct)));

        let messages_to_send = if let Some(receipt) = rcts_from_db {
            vec![Message::Notice(Notice::Event(message.clone())), receipt]
        } else {
            vec![Message::Notice(Notice::Event(message.clone()))]
        };

        let results = join_all(
            itertools::iproduct!(messages_to_send, witness_prefixes).map(
                |(message, witness_id)| {
                    self.send_message_to(
                        IdentifierPrefix::Basic(witness_id.clone()),
                        message.clone(),
                    )
                },
            ),
        )
        .await;

        // Publishing is best effort: an unreachable witness is caught up
        // later. A witness refusing the event because the identifier is
        // abandoned is final, though, so the caller has to know.
        match results.into_iter().find_map(|result| match result {
            Err(SendingError::ActorInternalError(ActorError::KeriError(
                keri_core::error::Error::AbandonedIdentifier(id),
            ))) => Some(id),
            _ => None,
        }) {
            Some(id) => Err(MechanicsError::IdentifierAbandoned(id)),
            None => Ok(()),
        }
    }

    /// Sends identifier's endpoint information to identifiers's watchers.
    // TODO use stream instead of json
    pub async fn send_oobi_to_watcher(
        &self,
        id: &IdentifierPrefix,
        oobi: &Oobi,
    ) -> Result<(), ControllerError> {
        for watcher in self.events.get_watchers(id)?.iter() {
            self.send_oobi_to(watcher, oobi.clone()).await?;
        }

        Ok(())
    }
}
