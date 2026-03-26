use std::sync::{Arc, RwLock};

use crate::{
    database::TelEventDatabase,
    error::Error,
    event::{manager_event::Config, verifiable_event::VerifiableEvent, Event},
    processor::{
        notification::{TelNotification, TelNotificationBus, TelNotificationKind, TelNotifier},
        storage::TelEventStorage,
        TelEventProcessor,
    },
    state::{vc_state::TelState, ManagerTelState},
};
use keri_core::{
    database::EventDatabase, prefix::IdentifierPrefix, processor::event_storage::EventStorage,
};
use said::SelfAddressingIdentifier;

pub mod event_generator;

pub struct RecentlyAddedEvents(RwLock<Vec<VerifiableEvent>>);
impl RecentlyAddedEvents {
    pub fn new() -> Self {
        Self(RwLock::new(Vec::new()))
    }

    pub fn get(&self) -> Vec<VerifiableEvent> {
        self.0.write().unwrap().drain(0..).collect()
    }
}
impl TelNotifier for RecentlyAddedEvents {
    fn notify(
        &self,
        notification: &TelNotification,
        _bus: &TelNotificationBus,
    ) -> Result<(), Error> {
        match notification {
            TelNotification::TelEventAdded(event) => self.0.write().unwrap().push(event.clone()),
            _ => return Err(Error::Generic("Wrong event type".to_string())),
        };
        Ok(())
    }
}

/// Transaction Event Log
pub struct Tel<D: TelEventDatabase, K: EventDatabase> {
    pub processor: TelEventProcessor<D, K>,
    pub recently_added_events: Arc<RecentlyAddedEvents>,
}

impl<D: TelEventDatabase, K: EventDatabase> Tel<D, K> {
    pub fn new(
        tel_reference: Arc<TelEventStorage<D>>,
        kel_reference: Arc<EventStorage<K>>,
        publisher: Option<TelNotificationBus>,
    ) -> Self {
        let added_events = Arc::new(RecentlyAddedEvents::new());
        publisher.as_ref().map(|r| {
            r.register_observer(
                added_events.clone(),
                vec![TelNotificationKind::TelEventAdded],
            )
        });
        Self {
            processor: TelEventProcessor::new(kel_reference, tel_reference, publisher),
            recently_added_events: added_events,
        }
    }

    pub fn make_inception_event(
        &self,
        issuer_prefix: IdentifierPrefix,
        config: Vec<Config>,
        backer_threshold: u64,
        backers: Vec<IdentifierPrefix>,
    ) -> Result<Event, Error> {
        event_generator::make_inception_event(
            issuer_prefix,
            config,
            backer_threshold,
            backers,
            None,
            None,
        )
    }

    pub fn make_rotation_event(
        &self,
        id: &IdentifierPrefix,
        ba: &[IdentifierPrefix],
        br: &[IdentifierPrefix],
    ) -> Result<Event, Error> {
        event_generator::make_rotation_event(
            &self
                .get_management_tel_state(id)?
                .ok_or(Error::UnknownIdentifierError)?,
            ba,
            br,
            None,
            None,
        )
    }

    pub fn make_issuance_event(
        &self,
        id: &IdentifierPrefix,
        vc_digest: SelfAddressingIdentifier,
    ) -> Result<Event, Error> {
        event_generator::make_issuance_event(
            &self
                .get_management_tel_state(id)?
                .ok_or(Error::UnknownIdentifierError)?,
            vc_digest,
            None,
            None,
        )
    }

    pub fn make_revoke_event(
        &self,
        register_id: &IdentifierPrefix,
        vc: &SelfAddressingIdentifier,
    ) -> Result<Event, Error> {
        let vc_state = self
            .get_vc_state(vc)?
            .ok_or(Error::UnknownIdentifierError)?;
        let last = match vc_state {
            TelState::Issued(last) => last,
            _ => return Err(Error::Generic("Inproper vc state".into())),
        };
        event_generator::make_revoke_event(
            vc,
            last,
            &self
                .get_management_tel_state(register_id)?
                .ok_or(Error::UnknownIdentifierError)?,
            None,
            None,
        )
    }

    pub fn parse_and_process_tel_stream(&self, stream: &[u8]) -> Result<(), Error> {
        let parsed = VerifiableEvent::parse(stream)?;
        for event in parsed {
            self.processor.process(event)?;
        }
        Ok(())
    }

    pub fn get_vc_state(
        &self,
        vc_hash: &SelfAddressingIdentifier,
    ) -> Result<Option<TelState>, Error> {
        let vc_prefix = IdentifierPrefix::self_addressing(vc_hash.to_owned());
        self.processor.tel_reference.compute_vc_state(&vc_prefix)
    }

    pub fn get_tel(
        &self,
        vc_hash: &SelfAddressingIdentifier,
    ) -> Result<Vec<VerifiableEvent>, Error> {
        let vc_events = self
            .processor
            .tel_reference
            .get_events(&IdentifierPrefix::self_addressing(vc_hash.clone()))?;
        let registry_id = vc_events[0].event.get_registry_id()?;
        Ok(self
            .processor
            .tel_reference
            .db
            .get_management_events(&registry_id)
            .unwrap()
            .chain(vc_events)
            .collect::<Vec<_>>())
    }

    pub fn get_management_tel<'a>(
        &'a self,
        registry_id: &'a IdentifierPrefix,
    ) -> Result<Option<Box<dyn DoubleEndedIterator<Item = VerifiableEvent> + 'a>>, Error> {
        Ok(self
            .processor
            .tel_reference
            .db
            .get_management_events(registry_id)
            .map(|iter| {
                Box::new(iter) as Box<dyn DoubleEndedIterator<Item = VerifiableEvent> + 'a>
            }))
    }

    pub fn get_management_tel_state(
        &self,
        id: &IdentifierPrefix,
    ) -> Result<Option<ManagerTelState>, Error> {
        self.processor
            .tel_reference
            .compute_management_tel_state(id)
    }
}
