use std::collections::HashSet;

use crate::error::ControllerError;
use keri_core::actor::prelude::HashFunctionCode;
use keri_core::{
    actor::{prelude::SerializationFormats, simple_controller::PossibleResponse},
    event::sections::seal::EventSeal,
    prefix::{BasicPrefix, IdentifierPrefix, SelfSigningPrefix},
    query::{
        mailbox::QueryArgsMbx,
        query_event::{LogsQueryArgs, QueryEvent, QueryRoute},
    },
};

use super::Identifier;

#[derive(Debug)]
pub enum QueryResponse {
    Updates,
    NoUpdates,
}

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
        &mut self,
        queries: Vec<(QueryEvent, SelfSigningPrefix)>,
    ) -> Result<QueryResponse, ControllerError> {
        let mut updates = QueryResponse::NoUpdates;
        let mut possibly_updated_ids: HashSet<IdentifierPrefix> = HashSet::new();
        for (qry, sig) in queries {
            match self.handle_query(&qry, sig).await? {
                PossibleResponse::Kel(kel) => {
                    for event in kel {
                        let id = event.get_prefix();
                        possibly_updated_ids.insert(id);
                        self.known_events.process(&event)?;
                    }
                }
                PossibleResponse::Mbx(mbx) => {
                    panic!("Unexpected response");
                }
                PossibleResponse::Ksn(_) => todo!(),
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
