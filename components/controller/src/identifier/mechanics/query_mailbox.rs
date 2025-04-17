use keri_core::actor::prelude::HashFunctionCode;
use keri_core::{
    actor::{prelude::SerializationFormats, simple_controller::PossibleResponse},
    oobi::Scheme,
    prefix::{BasicPrefix, IdentifierPrefix, IndexedSignature, SelfSigningPrefix},
    query::{
        mailbox::{MailboxQuery, MailboxRoute, QueryArgsMbx},
        query_event::SignedQuery,
    },
};

#[cfg(not(feature = "query_cache"))]
use crate::mailbox_updating::MailboxReminder;

use crate::{
    communication::SendingError,
    error::ControllerError,
    identifier::Identifier,
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

impl Identifier {
    /// Generates query message of route `mbx` to query own identifier mailbox.
    pub fn query_mailbox(
        &self,
        identifier: &IdentifierPrefix,
        witnesses: &[BasicPrefix],
    ) -> Result<Vec<MailboxQuery>, ControllerError> {
        witnesses
            .iter()
            .map(|wit| -> Result<_, ControllerError> {
                let recipient = IdentifierPrefix::Basic(wit.clone());

                #[cfg(feature = "query_cache")]
                let reminder = if identifier == &self.id {
                    // request own mailbox
                    self.query_cache.last_asked_index(&recipient)
                } else {
                    // request group mailbox
                    self.query_cache.last_asked_group_index(&recipient)
                }?;
                #[cfg(not(feature = "query_cache"))]
                let reminder = MailboxReminder::default();

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
                _ => panic!("Unexpected response"),
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
            .send_management_query_to(recipient.as_ref().unwrap(), Scheme::Http, query)
            .await
    }
}
