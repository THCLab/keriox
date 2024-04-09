use keri_core::{actor::{prelude::SerializationFormats, simple_controller::PossibleResponse}, event::sections::seal::EventSeal, mailbox::MailboxResponse, oobi::Scheme, prefix::{BasicPrefix, IdentifierPrefix, IndexedSignature, SelfSigningPrefix}, query::{mailbox::QueryArgsMbx, query_event::{LogsQueryArgs, QueryEvent, QueryRoute, SignedKelQuery}}};
use keri_core::actor::prelude::HashFunctionCode;
use crate::{error::ControllerError, mailbox_updating::ActionRequired};

use super::Identifier;

impl Identifier {
	/// Generates query message of route `mbx` to query own identifier mailbox.
    pub fn query_mailbox(
        &self,
        identifier: &IdentifierPrefix,
        witnesses: &[BasicPrefix],
    ) -> Result<Vec<QueryEvent>, ControllerError> {
        witnesses
            .iter()
            .map(|wit| -> Result<_, ControllerError> {
                let recipient = IdentifierPrefix::Basic(wit.clone());

                let reminder = if identifier == &self.id {
                    // request own mailbox
                    self.query_cache.last_asked_index(&recipient)
                } else {
                    // request group mailbox
                    self.query_cache.last_asked_group_index(&recipient)
                }?;

                Ok(QueryEvent::new_query(
                    QueryRoute::Mbx {
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
                )?)
            })
            .collect()
    }

    pub fn query_own_watchers(
        &self,
        about_who: &EventSeal,
    ) -> Result<Vec<QueryEvent>, ControllerError> {
        self.known_events
            .get_watchers(&self.id)?
            .into_iter()
            .map(|watcher| self.query_log(about_who, watcher))
            .collect()
    }

	/// Joins query events with their signatures, sends it to witness and
    /// process its response. If user action is needed to finalize process,
    /// returns proper notification.
    pub async fn finalize_query(
        &self,
        queries: Vec<(QueryEvent, SelfSigningPrefix)>,
    ) -> Result<Vec<ActionRequired>, ControllerError> {
        let self_id = self.id.clone();
        let mut actions = Vec::new();
        for (qry, sig) in queries {
            let (recipient, about_who, from_who) = match qry.get_route() {
                QueryRoute::Logs {
                    reply_route: _,
                    args,
                } => (args.src.clone(), Some(&args.i), Some(&self.id)),
                QueryRoute::Ksn {
                    reply_route: _,
                    args,
                } => (
                    args.src.clone(),
                    // .ok_or_else(|| {
                    //     ControllerError::QueryArgumentError(
                    //         "Missing query recipient identifier".into(),
                    //     )
                    // })?,
                    None,
                    None,
                ),
                QueryRoute::Mbx {
                    reply_route: _,
                    args,
                } => (Some(args.src.clone()), Some(&args.i), Some(&args.pre)),
            };
            let query = match &self.id {
                IdentifierPrefix::Basic(bp) => {
                    SignedKelQuery::new_nontrans(qry.clone(), bp.clone(), sig)
                }
                _ => {
                    let signatures = vec![IndexedSignature::new_both_same(sig, 0)];
                    SignedKelQuery::new_trans(qry.clone(), self_id.clone(), signatures)
                }
            };
            let res = self
                .communication
                .send_query_to(recipient.as_ref().unwrap(), Scheme::Http, query)
                .await?;

            match res {
                PossibleResponse::Kel(kel) => {
                    for event in kel {
                        self.known_events.process(&event)?;
                    }
                }
                PossibleResponse::Mbx(mbx) => {
                    // only process if we actually asked about mailbox
                    if let (Some(from_who), Some(about_who)) =
                        (from_who.as_ref(), about_who.as_ref())
                    {
                        actions.append(
                            &mut self
                                .mailbox_response(&recipient.unwrap(), from_who, about_who, &mbx)
                                .await?,
                        );
                    }
                }
                PossibleResponse::Ksn(_) => todo!(),
            };
        }
        Ok(actions)
    }

	async fn mailbox_response(
        &self,
        recipient: &IdentifierPrefix,
        from_who: &IdentifierPrefix,
        about_who: &IdentifierPrefix,
        res: &MailboxResponse,
    ) -> Result<Vec<ActionRequired>, ControllerError> {
        let req = if from_who == about_who {
            // process own mailbox
            let req = self.process_own_mailbox(res)?;
            self.query_cache.update_last_asked_index(recipient.clone(), res)?;
            req
        } else {
            // process group mailbox
            let group_req = self.process_group_mailbox(res, about_who).await?;
            self.query_cache.update_last_asked_group_index(recipient.clone(), res)?;
            group_req
        };
        Ok(req)
    }

    fn query_log(
        &self,
        seal: &EventSeal,
        watcher: IdentifierPrefix,
    ) -> Result<QueryEvent, ControllerError> {
        Ok(QueryEvent::new_query(
            QueryRoute::Logs {
                reply_route: "".to_string(),
                args: LogsQueryArgs {
                    s: Some(seal.sn),
                    i: seal.prefix.clone(),
                    src: Some(watcher),
                },
            },
            SerializationFormats::JSON,
            HashFunctionCode::Blake3_256,
        )?)
    }
}