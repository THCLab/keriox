use std::collections::HashSet;

use crate::communication::SendingError;
use crate::error::ControllerError;
use keri_core::actor::error::ActorError;
use keri_core::actor::prelude::HashFunctionCode;
use keri_core::oobi::Scheme;
use keri_core::prefix::IndexedSignature;
use keri_core::query::query_event::SignedKelQuery;
use keri_core::{
    actor::{prelude::SerializationFormats, simple_controller::PossibleResponse},
    event::sections::seal::EventSeal,
    prefix::{IdentifierPrefix, SelfSigningPrefix},
    query::query_event::{LogsQueryArgs, QueryEvent, QueryRoute},
};

use super::Identifier;

#[derive(Debug, PartialEq)]
pub enum QueryResponse {
    Updates,
    NoUpdates,
}

#[derive(thiserror::Error, Debug)]
pub enum WatcherResponseError {
    #[error("Unexpected watcher response")]
    UnexpectedResponse,
    #[error("Watcher response processing error: {0}")]
    ResponseProcessingError(#[from] keri_core::error::Error),
    #[error(transparent)]
    SendingError(#[from] SendingError),
    #[error("Response not ready")]
    ResponseNotReady,
}

impl Identifier {
    pub fn query_watchers(
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
        &mut self,
        queries: Vec<(QueryEvent, SelfSigningPrefix)>,
    ) -> Result<QueryResponse, WatcherResponseError> {
        let mut updates = QueryResponse::NoUpdates;
        let mut possibly_updated_ids: HashSet<IdentifierPrefix> = HashSet::new();
        for (qry, sig) in queries {
            match self.handle_query(&qry, sig).await {
                Ok(PossibleResponse::Kel(kel)) => {
                    for event in kel {
                        let id = event.get_prefix();
                        possibly_updated_ids.insert(id);
                        self.known_events.process(&event)?;
                    }
                }
                Ok(PossibleResponse::Mbx(_mbx)) => {
                    return Err(WatcherResponseError::UnexpectedResponse);
                }
                Ok(PossibleResponse::Ksn(_)) => todo!(),
                Err(SendingError::ActorInternalError(ActorError::ResponseNotReady)) => {
                    return Err(WatcherResponseError::ResponseNotReady)
                }
                Err(e) => return Err(e.into()),
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
        Ok(updates)
    }

    /// Joins query events with their signatures, sends it to witness.
    async fn handle_query(
        &self,
        qry: &QueryEvent,
        sig: SelfSigningPrefix,
    ) -> Result<PossibleResponse, SendingError> {
        let recipient = match qry.get_route() {
            QueryRoute::Logs {
                reply_route: _,
                args,
            } => args.src.clone(),
            QueryRoute::Ksn {
                reply_route: _,
                args,
            } => args.src.clone(),
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
        self.communication
            .send_query_to(recipient.as_ref().unwrap(), Scheme::Http, query)
            .await
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
