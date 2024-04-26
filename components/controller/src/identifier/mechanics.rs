use std::collections::HashSet;

use keri_core::{actor::{error::ActorError, simple_controller::PossibleResponse}, mailbox::MailboxResponse, oobi::Scheme, prefix::{IdentifierPrefix, IndexedSignature, SelfSigningPrefix}, query::query_event::{QueryEvent, QueryRoute, SignedKelQuery}, transport::TransportError};

use crate::{communication::SendingError, error::ControllerError, known_events::OobiRetrieveError, mailbox_updating::ActionRequired};

use super::{query::QueryResponse, Identifier};

pub struct Mechanics {

}

#[derive(Debug, thiserror::Error)]
pub enum MechanicsError {
	#[error("Watcher don't have identifier {0} oobi")]
	WatcherDontHaveOobi(IdentifierPrefix),

	#[error("Watcher internal error: {0}")]
	WatcherError(#[from] ActorError),

	#[error("Transport error: {0}")]
	Transport(#[from] TransportError),

	#[error("Can't lock")]
	LockingError,

	#[error("transparent")]
    EventProcessingError(#[from] keri_core::error::Error),

	#[error("No kel events for {0} saved")]
	UnknownIdentifierError(IdentifierPrefix),

	#[error("Can't generate event: {0}")]
    EventGenerationError(String),

    #[error("Not group participant")]
    NotGroupParticipantError,

    #[error("Error: {0}")]
    OtherError(String),

    #[error("Wrong event type")]
    WrongEventTypeError,

    #[error("Wrong event format")]
    EventFormatError,

    #[error("Inception event error: {0}")]
    InceptionError(String),

    #[error("Improper witness prefix, should be basic prefix")]
    WrongWitnessPrefixError,

}

impl From<SendingError> for MechanicsError {
	fn from(value: SendingError) -> Self {
		match value {
				SendingError::TransportError(TransportError::RemoteError(ActorError::NoIdentState { prefix })) => {
					MechanicsError::WatcherDontHaveOobi(prefix)
				},
				SendingError::TransportError(TransportError::RemoteError(err)) => {
					MechanicsError::WatcherError(err)
				},
				SendingError::TransportError(err) => MechanicsError::Transport(err),
				SendingError::OobiError(OobiRetrieveError::DbError(_)) => todo!(),
				SendingError::OobiError(OobiRetrieveError::MissingOobi(id, _)) => todo!(),
			}
	}
}

impl Identifier {
    pub async fn handle_query(&self, qry: &QueryEvent, sig: SelfSigningPrefix) -> Result<PossibleResponse, SendingError> {
            let recipient= match qry.get_route() {
                QueryRoute::Mbx {
                    reply_route: _,
                    args,
                } => Some(args.src.clone()),
                _ => {panic!("Wrong query route")}
            };
            let query = match &self.id {
                IdentifierPrefix::Basic(bp) => {
                    SignedKelQuery::new_nontrans(qry.clone(), bp.clone(), sig)
                }
                _ => {
                    let signatures = vec![IndexedSignature::new_both_same(sig, 0)];
                    SignedKelQuery::new_trans(qry.clone(), self.id().clone(), signatures)
                }
            };
            self
                .communication
                .send_query_to(recipient.as_ref().unwrap(), Scheme::Http, query)
                .await
    }


	 /// Joins query events with their signatures, sends it to witness and
    /// process its response. If user action is needed to finalize process,
    /// returns proper notification.
    pub async fn finalize_mechanics_query(
        &mut self,
        queries: Vec<(QueryEvent, SelfSigningPrefix)>,
    ) -> Result<QueryResponse, MechanicsError> {
        let self_id = self.id.clone();
        let mut actions = Vec::new();
        let mut updates = QueryResponse::NoUpdates;
        let mut possibly_updated_ids: HashSet<IdentifierPrefix> = HashSet::new();
        for (qry, sig) in queries {
            let (recipient, about_who, from_who) = match qry.get_route() {
                QueryRoute::Logs {
                    reply_route: _,
                    args,
                } => (args.src.clone(), Some(&args.i), Some(self.id())),
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
            let res = self.handle_query(&qry, sig).await?;
            match res {
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
                        if !mbx.receipt.is_empty() {
                            updates = QueryResponse::Updates;
                        }
                    }
                }
                PossibleResponse::Ksn(_) => todo!(),
				_ => panic!("Unexpected response")
            };
        }
        for id in possibly_updated_ids {
            let db_state = self.find_state(&id).ok();
            let cached_state = self.cached_identifiers.get(&id);
            if db_state.as_ref().eq(&cached_state) {
                updates = QueryResponse::NoUpdates
            } else {
                self.cached_identifiers.insert(id, db_state.unwrap());
                updates = QueryResponse::Updates
            }
        }
        if !actions.is_empty() {
            Ok(QueryResponse::ActionRequired(actions))
        } else {
            Ok(updates)
        }
    }

    pub async fn mailbox_response(
        &self,
        recipient: &IdentifierPrefix,
        from_who: &IdentifierPrefix,
        about_who: &IdentifierPrefix,
        res: &MailboxResponse,
    ) -> Result<Vec<ActionRequired>, MechanicsError> {
        let req = if from_who == about_who {
            // process own mailbox
            let req = self.process_own_mailbox(res)?;
            self.query_cache
                .update_last_asked_index(recipient.clone(), res)?;
            req
        } else {
            // process group mailbox
            let group_req = self.process_group_mailbox(res, about_who).await?;
            self.query_cache
                .update_last_asked_group_index(recipient.clone(), res)?;
            group_req
        };
        Ok(req)
    }
}