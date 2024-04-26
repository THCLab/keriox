use keri_core::{actor::{error::ActorError, simple_controller::PossibleResponse}, mailbox::MailboxResponse, oobi::Scheme, prefix::{IdentifierPrefix, IndexedSignature, SelfSigningPrefix}, query::query_event::{QueryEvent, QueryRoute, SignedKelQuery}, transport::TransportError};

use crate::{communication::SendingError, known_events::OobiRetrieveError, mailbox_updating::ActionRequired};

use super::Identifier;

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
    /// Joins query events with their signatures, sends it to witness.
    pub async fn handle_query(&self, qry: &QueryEvent, sig: SelfSigningPrefix) -> Result<PossibleResponse, SendingError> {
            let recipient= match qry.get_route() {
                QueryRoute::Logs {
                    reply_route: _,
                    args,
                } => args.src.clone(),
                QueryRoute::Ksn {
                    reply_route: _,
                    args,
                } => args.src.clone(),
                QueryRoute::Mbx {
                    reply_route: _,
                    args,
                } => Some(args.src.clone()),
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
    ) -> Result<Vec<ActionRequired>, MechanicsError> {
        let mut actions = Vec::new();
        for (qry, sig) in queries {
           match qry.get_route() {
                QueryRoute::Mbx {
                    reply_route: _,
                    args,
                } => { 
                    let (recipient, about_who, from_who) = (args.src.clone(), Some(&args.i), Some(&args.pre));
                     match self.handle_query(&qry, sig).await? {
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
                            }
                        }
                        _ => panic!("Unexpected response")
                    };
                },
                _ => panic!("Unexpected query format")
            };
           
        }
        
        Ok(actions)
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