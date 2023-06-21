use std::sync::Arc;

use keri::prefix::IdentifierPrefix;
use said::SelfAddressingIdentifier;

use crate::{
    database::EventDatabase,
    error::Error,
    event::{verifiable_event::VerifiableEvent, Event},
    state::{vc_state::TelState, ManagerTelState},
};

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
    ) -> Result<ManagerTelState, Error> {
        match self.db.get_management_events(id) {
            Some(events) => events.into_iter().fold(
                Ok(ManagerTelState::default()),
                |state: Result<ManagerTelState, Error>,
                 ev: VerifiableEvent|
                 -> Result<ManagerTelState, Error> {
                    match ev.event {
                        Event::Management(event) => state?.apply(&event),
                        Event::Vc(_) => Err(Error::Generic("Improper event type".into())),
                    }
                },
            ),
            None => Ok(ManagerTelState::default()),
        }
    }

    pub fn compute_vc_state(&self, vc_id: &IdentifierPrefix) -> Result<TelState, Error> {
        match self.db.get_events(vc_id) {
            Some(events) => events.into_iter().fold(
                Ok(TelState::default()),
                |state, ev| -> Result<TelState, Error> {
                    match ev.event {
                        Event::Vc(event) => state?.apply(&event),
                        _ => state,
                    }
                },
            ),
            None => Ok(TelState::default()),
        }
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

    pub fn get_events(
        &self,
        vc_id: &SelfAddressingIdentifier,
    ) -> Result<Vec<VerifiableEvent>, Error> {
        let prefix = IdentifierPrefix::SelfAddressing(vc_id.to_owned());
        match self.db.get_events(&prefix) {
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
}
