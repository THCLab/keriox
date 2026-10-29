//! Witnessing without a mailbox. A controller collects its witnesses'
//! receipts by asking each witness for the key event log it witnesses, and
//! the forwards that carry group events and delegation requests between
//! identifiers are delivered by the application, through any channel, such
//! as a messagebox: the controller makes them ([`Forward`]) and takes them
//! back ([`Identifier::receive_forwards`]).

use keri_core::{
    actor::{prelude::Message, verify_forward},
    database::{EscrowCreator, EventDatabase},
    event_message::{cesr_adapter::parse_cesr_stream_many, signed_event_message::Op},
    mailbox::exchange::ForwardTopic,
    oobi_manager::storage::OobiStorageBackend,
    prefix::{BasicPrefix, IdentifierPrefix, SelfSigningPrefix},
    query::query_event::{QueryEvent, QueryRoute},
};
use teliox::registry::RegistryStore;

use crate::{
    error::ControllerError,
    identifier::{query::WatcherResponseError, Identifier},
    mailbox_updating::ActionRequired,
};

use super::MechanicsError;

#[derive(Debug, thiserror::Error)]
pub enum ResponseProcessingError {
    #[error("Unexpected response")]
    UnexpectedResponse,
    #[error("Error while processing receipts from response: {0}")]
    Receipts(keri_core::error::Error),
    #[error("Error while processing multisig from response: {0}")]
    Multisig(keri_core::error::Error),
    #[error("Error while processing delegate from response: {0}")]
    Delegate(keri_core::error::Error),
}

/// A forward to deliver: the identifier it is for, and the signed
/// exchange, with the key event it forwards nested in it. A forward for a
/// group goes to each of the group's members.
#[derive(Debug, Clone, PartialEq)]
pub struct Forward {
    pub to: IdentifierPrefix,
    pub message: Vec<u8>,
}

impl<D, T, S> Identifier<D, T, S>
where
    D: EventDatabase + EscrowCreator + Send + Sync + 'static,
    T: RegistryStore + Send + Sync + 'static,
    S: OobiStorageBackend,
{
    /// Key event log queries about `about` (this identifier, or a group it
    /// is a member of) to its `witnesses`, whose answers carry the events
    /// with the witnesses' receipts. Sign each and pass them to
    /// [`Self::finalize_query_receipts`].
    pub fn query_receipts(
        &self,
        about: &IdentifierPrefix,
        witnesses: &[BasicPrefix],
    ) -> Result<Vec<QueryEvent>, ControllerError> {
        witnesses
            .iter()
            .map(|witness| self.query_full_log(about, IdentifierPrefix::Basic(witness.clone())))
            .collect()
    }

    /// Sends the signed receipt queries, takes in the events and receipts
    /// the witnesses answer with, and passes this identifier's receipts on
    /// to its witnesses and to the witnesses asked, so that each witness
    /// learns the others' receipts however the queries are split across
    /// calls. A witness that cannot answer yet is no error: its answer is
    /// returned among the others.
    pub async fn finalize_query_receipts(
        &mut self,
        queries: Vec<(QueryEvent, SelfSigningPrefix)>,
    ) -> Result<Vec<WatcherResponseError>, ControllerError> {
        let mut witnesses = self
            .witnesses()
            .map(IdentifierPrefix::Basic)
            .collect::<Vec<_>>();
        for asked in queries.iter().filter_map(|(query, _)| match query.get_route() {
            QueryRoute::Logs { args, .. } => args.src.clone(),
            _ => None,
        }) {
            if !witnesses.contains(&asked) {
                witnesses.push(asked);
            }
        }
        let (_, errors) = self.finalize_query(queries).await;
        self.broadcast_receipts(&witnesses)
            .await
            .map_err(MechanicsError::BroadcastingError)?;
        Ok(errors)
    }

    /// Takes forwards delivered to this identifier, or to a group it is a
    /// member of: verifies each against its sender's key state, takes in
    /// the event it forwards, and returns what needs this identifier's
    /// signature (a group event to co-sign, a delegation to approve). The
    /// senders' key event logs must be known here.
    pub async fn receive_forwards(
        &mut self,
        stream: &[u8],
    ) -> Result<Vec<ActionRequired>, ControllerError> {
        let mut actions = vec![];
        for message in parse_cesr_stream_many(stream)
            .map_err(|e| ControllerError::OtherError(e.to_string()))?
        {
            let message = Message::try_from(message)
                .map_err(|e| ControllerError::OtherError(e.to_string()))?;
            let Message::Op(Op::Exchange(exchange)) = message else {
                return Err(ControllerError::OtherError(
                    "only forwards are delivered to a controller".into(),
                ));
            };
            let forwarded = verify_forward(&exchange, &self.known_events.storage)
                .map_err(MechanicsError::EventProcessingError)?;
            let action = match (forwarded.topic, forwarded.recipient == self.id) {
                (ForwardTopic::Multisig, true) => {
                    Some(self.process_own_multisig(&forwarded.event)?)
                }
                (ForwardTopic::Delegate, true) => self.process_own_delegate(&forwarded.event)?,
                (ForwardTopic::Multisig, false) => {
                    self.process_group_multisig(&forwarded.event).await?
                }
                (ForwardTopic::Delegate, false) => {
                    self.process_group_delegate(&forwarded.event, &forwarded.recipient)
                        .await?
                }
            };
            actions.extend(action);
        }
        Ok(actions)
    }
}
