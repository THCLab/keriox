use std::sync::Arc;

use crate::{
    error::Error,
    event::manager_event::Config,
    event::verifiable_event::VerifiableEvent,
    event::Event,
    processor::{notification::TelNotificationBus, storage::TelEventStorage, TelEventProcessor},
    state::{vc_state::TelState, ManagerTelState},
};
use keri::{prefix::IdentifierPrefix, processor::event_storage::EventStorage};
use said::{
    derivation::{HashFunction, HashFunctionCode},
    SelfAddressingIdentifier,
};

pub mod event_generator;

/// Transaction Event Log
pub struct Tel {
    pub processor: TelEventProcessor,
    pub tel_prefix: IdentifierPrefix,
}

impl Tel {
    pub fn new(
        tel_reference: Arc<TelEventStorage>,
        kel_reference: Arc<EventStorage>,
        publisher: Option<TelNotificationBus>,
    ) -> Self {
        Self {
            processor: TelEventProcessor::new(kel_reference, tel_reference, publisher),
            tel_prefix: IdentifierPrefix::default(),
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
        derivation: HashFunctionCode,
        vc: &str,
    ) -> Result<Event, Error> {
        let vc_hash = HashFunction::from(derivation).derive(vc.as_bytes());
        event_generator::make_issuance_event(
            &self
                .get_management_tel_state(id)?
                .ok_or(Error::UnknownIdentifierError)?,
            vc_hash,
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

    // Process verifiable event. It doesn't check if source seal is correct. Just add event to tel.
    pub fn process(&mut self, event: VerifiableEvent) -> Result<(), Error> {
        self.processor.process(event.clone())?;
        // If tel prefix is not set yet, set it to first processed management event identifier prefix.
        if self.tel_prefix == IdentifierPrefix::default() {
            if let Event::Management(man) = event.event {
                self.tel_prefix = man.data.prefix.to_owned()
            }
        }
        Ok(())
    }

    pub fn get_vc_state(
        &self,
        vc_hash: &SelfAddressingIdentifier,
    ) -> Result<Option<TelState>, Error> {
        let vc_prefix = IdentifierPrefix::SelfAddressing(vc_hash.to_owned());
        self.processor.tel_reference.compute_vc_state(&vc_prefix)
    }

    pub fn get_tel(
        &self,
        vc_hash: &SelfAddressingIdentifier,
    ) -> Result<Vec<VerifiableEvent>, Error> {
        self.processor.tel_reference.get_events(vc_hash)
    }

    pub fn get_management_tel_state(
        &self,
        id: &IdentifierPrefix,
    ) -> Result<Option<ManagerTelState>, Error> {
        self.processor
            .tel_reference
            .compute_management_tel_state(&id)
    }
}
