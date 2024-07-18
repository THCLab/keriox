use std::sync::Arc;

use keri_core::{
    event::{
        event_data::{EventData, InteractionEvent},
        sections::seal::Seal,
    },
    prefix::IdentifierPrefix,
    processor::event_storage::EventStorage,
};
use said::SelfAddressingIdentifier;

use crate::{
    database::EventDatabase,
    error::Error,
    event::{
        manager_event::{ManagerEventType, ManagerTelEventMessage},
        vc_event::VCEventMessage,
        verifiable_event::VerifiableEvent,
        Event,
    },
    seal::AttachedSourceSeal,
};

use super::TelEventStorage;

pub struct TelEventValidator {
    kel_reference: Arc<EventStorage>,
    db: TelEventStorage,
}

impl TelEventValidator {
    pub fn new(db: Arc<EventDatabase>, kel_reference: Arc<EventStorage>) -> Self {
        Self {
            db: TelEventStorage::new(db),
            kel_reference,
        }
    }

    /// Checks if kel event pointed by seal has seal to tel event inside.
    pub fn check_kel_event(
        kel_reference: Arc<EventStorage>,
        seal: &AttachedSourceSeal,
        issuer_id: &IdentifierPrefix,
        expected_digest: SelfAddressingIdentifier,
    ) -> Result<(), Error> {
        let reference_kel_event = kel_reference
            .get_event_at_sn(issuer_id, seal.seal.sn)
            .ok_or(Error::MissingIssuerEventError)?;
        // Check if digest of found event matches digest from seal
        match &reference_kel_event
            .signed_event_message
            .event_message
            .digest
        {
            Some(dig) if dig == &seal.seal.digest => Ok(()),
            _ => Err(Error::DigestsNotMatchError),
        }?;
        // Check if found event has tel event anchored
        let event_type = reference_kel_event
            .signed_event_message
            .event_message
            .data
            .event_data;
        if let EventData::Ixn(InteractionEvent {
            data,
            previous_event_hash: _,
        }) = event_type
        {
            if data.into_iter().any(|seal| match seal {
                Seal::Event(es) => es.event_digest.eq(&expected_digest),
                _ => false,
            }) {
                Ok(())
            } else {
                Err(Error::MissingSealError)
            }
        } else {
            Err(Error::Generic("Wrong event type".to_string()))
        }
    }

    pub fn validate_management(
        &self,
        event: &ManagerTelEventMessage,
        seal: &AttachedSourceSeal,
    ) -> Result<(), Error> {
        let id = match &event.data.event_type {
            ManagerEventType::Vcp(vcp) => vcp.issuer_id.clone(),
            ManagerEventType::Vrt(_vrt) => {
                self.db
                    .compute_management_tel_state(&event.data.prefix)?
                    .ok_or(Error::MissingRegistryError)?
                    .issuer
            }
        };

        Self::check_kel_event(
            self.kel_reference.clone(),
            seal,
            &id,
            event.digest().unwrap(),
        )?;

        let state = self
            .db
            .compute_management_tel_state(&event.data.prefix)?
            .unwrap_or_default();

        state.apply(event)?;

        Ok(())
    }

    pub fn validate_vc(
        &self,
        vc_event: &VCEventMessage,
        seal: &AttachedSourceSeal,
    ) -> Result<(), Error> {
        let registry_id = vc_event.data.data.registry_id()?;
        let issuer_id = self
            .db
            .compute_management_tel_state(&registry_id)?
            .ok_or(Error::MissingRegistryError)?
            .issuer;
        Self::check_kel_event(
            self.kel_reference.clone(),
            seal,
            &issuer_id,
            vc_event.digest().unwrap(),
        )?;
        self.db
            .compute_vc_state(&vc_event.data.data.prefix)?
            .unwrap_or_default()
            .apply(vc_event)?;

        Ok(())
    }
    pub fn validate(&self, verifiable_event: &VerifiableEvent) -> Result<(), Error> {
        match verifiable_event.event {
            Event::Management(ref man) => self.validate_management(man, &verifiable_event.seal),
            Event::Vc(ref vc) => self.validate_vc(vc, &verifiable_event.seal),
        }
    }
}
