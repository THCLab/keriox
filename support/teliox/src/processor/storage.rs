use std::sync::Arc;

use keri::prefix::IdentifierPrefix;

use crate::{
    database::EventDatabase,
    error::Error,
    event::{verifiable_event::VerifiableEvent, Event},
    query::TelQueryRoute,
    state::{vc_state::TelState, ManagerTelState},
};

use super::TelReplyType;

pub struct TelEventStorage {
    pub db: Arc<EventDatabase>,
}
impl TelEventStorage {
    pub fn new(db: Arc<EventDatabase>) -> Self {
        Self { db }
    }

    pub fn compute_management_tel_state(
        &self,
        id: &IdentifierPrefix,
    ) -> Result<Option<ManagerTelState>, Error> {
        self.db
            .get_management_events(id)
            .map(|events| {
                events.fold(
                    Ok(ManagerTelState::default()),
                    |state: Result<ManagerTelState, Error>,
                     ev: VerifiableEvent|
                     -> Result<ManagerTelState, Error> {
                        match ev.event {
                            Event::Management(event) => state?.apply(&event),
                            Event::Vc(_) => Err(Error::Generic("Improper event type".into())),
                        }
                    },
                )
            })
            .transpose()
    }

    pub fn compute_vc_state(&self, vc_id: &IdentifierPrefix) -> Result<Option<TelState>, Error> {
        self.db
            .get_events(vc_id)
            .map(|events| {
                events.into_iter().fold(
                    Ok(TelState::default()),
                    |state, ev| -> Result<TelState, Error> {
                        match ev.event {
                            Event::Vc(event) => state?.apply(&event),
                            _ => state,
                        }
                    },
                )
            })
            .transpose()
    }

    pub fn get_management_events(&self, id: &IdentifierPrefix) -> Result<Option<Vec<u8>>, Error> {
        match self.db.get_management_events(id) {
            Some(events) => Ok(Some(
                events
                    .map(|event| event.serialize().unwrap_or_default())
                    .fold(vec![], |mut accum, serialized_event| {
                        accum.extend(serialized_event);
                        accum
                    }),
            )),
            None => Ok(None),
        }
    }

    pub fn get_events(&self, vc_id: &IdentifierPrefix) -> Result<Vec<VerifiableEvent>, Error> {
        match self.db.get_events(&vc_id) {
            Some(events) => Ok(events.collect()),
            None => Ok(vec![]),
        }
    }

    pub fn get_management_event_at_sn(
        &self,
        id: &IdentifierPrefix,
        sn: u64,
    ) -> Result<Option<VerifiableEvent>, Error> {
        match self.db.get_management_events(id) {
            Some(mut events) => Ok(events.find(|event| {
                if let Event::Management(man) = &event.event {
                    man.data.sn == sn
                } else {
                    false
                }
            })),
            None => Ok(None),
        }
    }

    pub fn add_event(&self, event: VerifiableEvent) -> Result<(), Error> {
        match &event.event {
            Event::Management(_man) => self
                .db
                .add_new_management_event(event.clone(), &event.get_event().get_prefix()),
            Event::Vc(_vc) => self
                .db
                .add_new_event(event.clone(), &event.get_event().get_prefix()),
        }
    }

    pub fn process_query(&self, qry: &TelQueryRoute) -> Result<TelReplyType, Error> {
        match qry {
            TelQueryRoute::Tels { reply_route:_, args } => {
                let management_tel = self
                    .get_management_events(args.ri.as_ref().unwrap())?
                    .unwrap();
                let vc_tel = self
                    .get_events(&args.i.as_ref().unwrap())?
                    .into_iter()
                    .map(|event| event.serialize().unwrap())
                    .flatten();
                Ok(TelReplyType::Tel(
                    management_tel.into_iter().chain(vc_tel).collect(),
                ))
            }
        }
    }
}
