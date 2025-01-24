use std::collections::HashSet;

use crate::communication::SendingError;
use crate::error::ControllerError;
use futures::future::join_all;
use keri_core::actor::error::ActorError;
use keri_core::actor::prelude::HashFunctionCode;
use keri_core::error::Error;
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
    #[error("Watcher response processing error: {0:?}")]
    ResponseProcessingError(Vec<keri_core::error::Error>),
    #[error(transparent)]
    SendingError(#[from] SendingError),
    #[error("KEL of {0} not found")]
    KELNotFound(IdentifierPrefix),
    #[error("Poison error")]
    PoisonError,
}

impl Identifier {
    pub fn query_watchers(
        &self,
        about_who: &EventSeal,
    ) -> Result<Vec<QueryEvent>, ControllerError> {
        self.known_events
            .get_watchers(&self.id)?
            .into_iter()
            .map(|watcher| self.query_log_range(&about_who.prefix, 0, about_who.sn, watcher))
            .collect()
    }

    async fn finalize_single_query(
        &self,
        qry: QueryEvent,
        sig: SelfSigningPrefix,
    ) -> Result<HashSet<IdentifierPrefix>, WatcherResponseError> {
        match self.handle_query(qry, sig).await {
            Ok(PossibleResponse::Kel(kel)) => {
                let mut possibly_updated_ids = HashSet::new();
                let errs = kel
                    .into_iter()
                    .filter_map(|event| {
                        let id = event.get_prefix();
                        possibly_updated_ids.insert(id);
                        match self.known_events.process(&event) {
                            Ok(_) => None,
                            Err(err) => Some(err),
                        }
                    })
                    .collect::<Vec<Error>>();
                if errs.is_empty() {
                    Ok(possibly_updated_ids)
                } else {
                    Err(WatcherResponseError::ResponseProcessingError(errs))
                }
            }
            Ok(PossibleResponse::Mbx(_mbx)) => Err(WatcherResponseError::UnexpectedResponse),
            Ok(PossibleResponse::Ksn(_)) => Err(WatcherResponseError::UnexpectedResponse),
            Err(SendingError::ActorInternalError(ActorError::NotFound(id))) => {
                Err(WatcherResponseError::KELNotFound(id))
            }
            Err(e) => Err(e.into()),
        }
    }

    /// Joins query events with their signatures, sends it to recipient and
    /// process its response. Returns a tuple containing two elements:
    ///     1. A notification if any identifier's KEL (Key Event Log) was updated.
    ///     2. A list of errors that occurred either during sending or on the recipient side.
    pub async fn finalize_query(
        &self,
        queries: Vec<(QueryEvent, SelfSigningPrefix)>,
    ) -> (QueryResponse, Vec<WatcherResponseError>) {
        let mut updates = QueryResponse::NoUpdates;
        let res = join_all(
            queries
                .into_iter()
                .map(|(qry, sig)| self.finalize_single_query(qry, sig)),
        )
        .await;

        let (possibly_updated_ids, mut errs) =
            res.into_iter()
                .fold(
                    (HashSet::new(), vec![]),
                    |(mut oks, mut errs), result| match result {
                        Ok(set) => {
                            for id in set {
                                oks.insert(id);
                            }
                            (oks, errs)
                        }
                        Err(e) => {
                            errs.push(e);
                            (oks, errs)
                        }
                    },
                );

        for id in possibly_updated_ids {
            let db_state = self.find_state(&id).ok();

            let cached_state = match self.cached_identifiers.lock() {
                Ok(ids) => ids.get(&id).map(|a| a.clone()),
                Err(_e) => {
                    errs.push(WatcherResponseError::PoisonError);
                    None
                }
            };

            if db_state.as_ref().eq(&cached_state.as_ref()) {
                updates = QueryResponse::NoUpdates
            } else {
                match self.cached_identifiers.lock() {
                    Ok(mut ids) => {
                        ids.insert(id, db_state.unwrap());
                    }
                    Err(_e) => errs.push(WatcherResponseError::PoisonError),
                };
                updates = QueryResponse::Updates
            }
        }
        (updates, errs)
    }

    /// Joins query events with their signatures, sends it to witness.
    async fn handle_query(
        &self,
        qry: QueryEvent,
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

    fn query_log_range(
        &self,
        id: &IdentifierPrefix,
        sn: u64,
        limit: u64,
        watcher: IdentifierPrefix,
    ) -> Result<QueryEvent, ControllerError> {
        Ok(QueryEvent::new_query(
            QueryRoute::Logs {
                reply_route: "".to_string(),
                args: LogsQueryArgs {
                    s: Some(sn),
                    i: id.clone(),
                    src: Some(watcher),
                    limit: Some(limit),
                },
            },
            SerializationFormats::JSON,
            HashFunctionCode::Blake3_256,
        ))
    }

    pub fn query_full_log(
        &self,
        id: &IdentifierPrefix,
        watcher: IdentifierPrefix,
    ) -> Result<QueryEvent, ControllerError> {
        Ok(QueryEvent::new_query(
            QueryRoute::Logs {
                reply_route: "".to_string(),
                args: LogsQueryArgs {
                    s: None,
                    i: id.clone(),
                    src: Some(watcher),
                    limit: None,
                },
            },
            SerializationFormats::JSON,
            HashFunctionCode::Blake3_256,
        ))
    }
}
