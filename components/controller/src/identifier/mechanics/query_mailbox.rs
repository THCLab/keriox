use keri_core::actor::possible_response::PossibleResponse;
use keri_core::actor::prelude::HashFunctionCode;
use keri_core::database::{EscrowCreator, EventDatabase};
use keri_core::oobi_manager::storage::OobiStorageBackend;
use keri_core::{
    actor::prelude::SerializationFormats,
    prefix::{BasicPrefix, IdentifierPrefix, IndexedSignature, SelfSigningPrefix},
    query::{
        mailbox::{MailboxQuery, MailboxRoute, QueryArgsMbx},
        query_event::SignedQuery,
    },
};
use teliox::database::TelEventDatabase;

use crate::{
    communication::SendingError, error::ControllerError, identifier::Identifier,
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

impl<D, T, S> Identifier<D, T, S>
where
    D: EventDatabase + EscrowCreator + Send + Sync + 'static,
    T: TelEventDatabase + Send + Sync + 'static,
    S: OobiStorageBackend,
{
    /// Generates query message of route `mbx` to query own identifier mailbox.
    /// Ask for `identifier`'s whole mailbox again on the next query.
    ///
    /// Mailbox reads are positional and advance by what a response
    /// carried, so an item that arrived before it could be used is
    /// never offered a second time. A caller that is still waiting on
    /// something the mailbox already delivered — a receipt for an event
    /// that had not yet cleared its delegation escrow, for instance —
    /// uses this to rewind.
    pub fn reset_group_mailbox_index(
        &self,
        identifier: &IdentifierPrefix,
        witnesses: &[BasicPrefix],
    ) -> Result<(), ControllerError> {
        for wit in witnesses {
            self.query_cache
                .reset_last_asked_group_index(identifier, &IdentifierPrefix::Basic(wit.clone()))?;
        }
        Ok(())
    }

    pub fn query_mailbox(
        &self,
        identifier: &IdentifierPrefix,
        witnesses: &[BasicPrefix],
    ) -> Result<Vec<MailboxQuery>, ControllerError> {
        witnesses
            .iter()
            .map(|wit| -> Result<_, ControllerError> {
                let recipient = IdentifierPrefix::Basic(wit.clone());

                let reminder = if identifier == &self.id {
                    // request own mailbox
                    self.query_cache.last_asked_index(identifier, &recipient)
                } else {
                    // request group mailbox
                    self.query_cache
                        .last_asked_group_index(identifier, &recipient)
                }?;

                Ok(MailboxQuery::new_query(
                    MailboxRoute::Mbx {
                        args: QueryArgsMbx {
                            // about who
                            i: identifier.clone(),
                            // who is asking
                            pre: self.id.clone(),
                            // who will get the query
                            src: recipient,
                            topics: reminder.to_query_topics(),
                        },
                        reply_route: "".to_string(),
                    },
                    &self.id,
                    self.known_events.version,
                    SerializationFormats::JSON,
                    HashFunctionCode::Blake3_256,
                ))
            })
            .collect()
    }

    /// Joins query events with their signatures, sends it to witness and
    /// process its response. If user action is needed to finalize process,
    /// returns proper notification.
    pub async fn finalize_query_mailbox(
        &mut self,
        queries: Vec<(MailboxQuery, SelfSigningPrefix)>,
    ) -> Result<Vec<ActionRequired>, ControllerError> {
        let mut actions = Vec::new();
        for (qry, sig) in queries {
            let args = qry.get_args();
            let (recipient, about_who, from_who) =
                (args.src.clone(), Some(&args.i), Some(&args.pre));
            match self.handle_management_query(&qry, sig).await? {
                PossibleResponse::Mbx(mbx) => {
                    // only process if we actually asked about mailbox
                    if let (Some(from_who), Some(about_who)) =
                        (from_who.as_ref(), about_who.as_ref())
                    {
                        actions.append(
                            &mut self
                                .mailbox_response(&recipient, from_who, about_who, &mbx)
                                .await?,
                        );
                        let witnesses = self
                            .witnesses()
                            .map(IdentifierPrefix::Basic)
                            .collect::<Vec<_>>();
                        self.broadcast_receipts(&witnesses)
                            .await
                            .map_err(MechanicsError::BroadcastingError)?;
                    }
                }
                _ => {
                    return Err(MechanicsError::ResponseProcessingError(
                        ResponseProcessingError::UnexpectedResponse,
                    )
                    .into())
                }
            };
        }

        Ok(actions)
    }

    /// Joins query events with their signatures, sends it to witness.
    async fn handle_management_query(
        &self,
        qry: &MailboxQuery,
        sig: SelfSigningPrefix,
    ) -> Result<PossibleResponse, SendingError> {
        let recipient = match &qry.data.data {
            MailboxRoute::Mbx {
                reply_route: _,
                args,
            } => Some(args.src.clone()),
        };

        let query = match &self.id {
            IdentifierPrefix::Basic(bp) => SignedQuery::new_nontrans(qry.clone(), bp.clone(), sig),
            _ => {
                let signatures = vec![IndexedSignature::new_both_same(sig, 0)];
                SignedQuery::new_trans(qry.clone(), self.id().clone(), signatures)
            }
        };
        self.communication
            .send_management_query_to(recipient.as_ref().unwrap(), query)
            .await
    }
}

#[cfg(test)]
mod test {
    use std::{collections::HashMap, sync::Arc};

    use keri_core::{
        actor::{error::ActorError, possible_response::PossibleResponse},
        event_message::signed_event_message::{Message, Op},
        oobi::{LocationScheme, Oobi, Role, Scheme},
        oobi_manager::RedbOobiStorage,
        prefix::{BasicPrefix, IdentifierPrefix, SelfSigningPrefix},
        query::query_event::SignedQueryMessage,
        signer::{CryptoBox, KeyManager},
        transport::test::{TestActor, TestActorMap, TestTransport},
    };
    use tempfile::Builder;
    use url::{Host, Url};
    use witness::{WitnessEscrowConfig, WitnessListener};

    use super::ResponseProcessingError;
    use crate::{
        config::ControllerConfig, controller::Controller, error::ControllerError,
        identifier::mechanics::MechanicsError,
    };

    /// A real witness, except that it answers every query with a key event
    /// log instead of what was asked for.
    struct OffRouteWitness(Arc<WitnessListener<RedbOobiStorage>>);

    #[async_trait::async_trait]
    impl TestActor for OffRouteWitness {
        async fn send_message(&self, msg: Message) -> Result<(), ActorError> {
            self.0.send_message(msg).await
        }
        async fn send_query(
            &self,
            _query: SignedQueryMessage,
        ) -> Result<PossibleResponse, ActorError> {
            Ok(PossibleResponse::Kel(vec![]))
        }
        async fn request_loc_scheme(&self, eid: IdentifierPrefix) -> Result<Vec<Op>, ActorError> {
            self.0.request_loc_scheme(eid).await
        }
        async fn request_end_role(
            &self,
            cid: IdentifierPrefix,
            role: Role,
            eid: IdentifierPrefix,
        ) -> Result<Vec<u8>, ActorError> {
            self.0.request_end_role(cid, role, eid).await
        }
        async fn resolve_oobi(&self, msg: Oobi) -> Result<(), ActorError> {
            self.0.resolve_oobi(msg).await
        }
    }

    #[async_std::test]
    async fn a_witness_answering_a_mailbox_query_with_something_else_is_an_error() {
        let root = Builder::new().prefix("mbx-off-route").tempdir().unwrap();
        let witness_root = Builder::new()
            .prefix("mbx-off-route-wit")
            .tempdir()
            .unwrap();
        let witness = Arc::new(
            WitnessListener::setup_with_redb(
                Url::parse("http://witness1:3232/").unwrap(),
                witness_root.path(),
                None,
                WitnessEscrowConfig::default(),
                keri_core::event_message::keri_version::KeriVersion::V1_0,
            )
            .unwrap(),
        );
        let witness_id = witness.get_prefix();
        let witness_location = LocationScheme {
            eid: IdentifierPrefix::Basic(witness_id.clone()),
            scheme: Scheme::Http,
            url: Some(Url::parse("http://witness1:3232").unwrap()),
        };
        let mut actors: TestActorMap = HashMap::new();
        actors.insert(
            (Host::Domain("witness1".to_string()), 3232),
            Arc::new(OffRouteWitness(witness)),
        );
        let controller = Controller::new(ControllerConfig {
            db_path: root.path().to_owned(),
            transport: Box::new(TestTransport::new(actors)),
            ..Default::default()
        })
        .unwrap();

        let keys = CryptoBox::new().unwrap();
        let icp = controller
            .incept(
                vec![BasicPrefix::Ed25519(keys.public_key())],
                vec![BasicPrefix::Ed25519(keys.next_public_key())],
                vec![witness_location],
                1,
            )
            .await
            .unwrap();
        let icp_sig = SelfSigningPrefix::Ed25519Sha512(keys.sign(icp.as_bytes()).unwrap());
        let mut identifier = controller
            .finalize_incept(icp.as_bytes(), &icp_sig)
            .unwrap();

        let queries = identifier
            .query_mailbox(identifier.id(), &[witness_id])
            .unwrap()
            .into_iter()
            .map(|qry| {
                let sig = keys.sign(&qry.encode().unwrap()).unwrap();
                (qry, SelfSigningPrefix::Ed25519Sha512(sig))
            })
            .collect();

        let result = identifier.finalize_query_mailbox(queries).await;

        assert!(
            matches!(
                result,
                Err(ControllerError::Mechanic(
                    MechanicsError::ResponseProcessingError(
                        ResponseProcessingError::UnexpectedResponse
                    )
                ))
            ),
            "expected UnexpectedResponse, got {result:?}"
        );
    }
}
