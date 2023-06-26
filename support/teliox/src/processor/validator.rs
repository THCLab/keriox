use std::sync::Arc;

use keri::processor::{event_storage::EventStorage, validator::EventValidator};

use crate::{
    database::EventDatabase,
    error::Error,
    event::{
        manager_event::ManagerTelEventMessage, vc_event::VCEventMessage,
        verifiable_event::VerifiableEvent, Event,
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
    pub fn validate_management(
        &self,
        event: &ManagerTelEventMessage,
        seal: &AttachedSourceSeal,
    ) -> Result<(), Error> {
        let id = match &event.data.event_type {
            crate::event::manager_event::ManagerEventType::Vcp(vcp) => vcp.issuer_id.clone(),
            crate::event::manager_event::ManagerEventType::Vrt(vrt) => todo!(),
        };
        let digest = seal.seal.digest.clone();
        let sn = seal.seal.sn.clone();

        let reference_kel_event = self
            .kel_reference
            .get_event_at_sn(&id, sn)?
            .ok_or(Error::MissingIssuerEventError)?;
        if digest.ne(&reference_kel_event
            .signed_event_message
            .event_message
            .digest
            .unwrap())
        {
            return Err(Error::DigestsNotMatchError);
        };

        if match reference_kel_event
            .signed_event_message
            .event_message
            .data
            .event_data
        {
            keri::event::event_data::EventData::Dip(_) => todo!(),
            keri::event::event_data::EventData::Icp(_) => todo!(),
            keri::event::event_data::EventData::Rot(_) => todo!(),
            keri::event::event_data::EventData::Ixn(ixn) => {
                ixn.data.into_iter().find(|seal| match seal {
                    keri::event::sections::seal::Seal::Location(_) => todo!(),
                    keri::event::sections::seal::Seal::Event(es) => {
                        es.event_digest.eq(&event.digest.as_ref().unwrap())
                    }
                    keri::event::sections::seal::Seal::Digest(_) => todo!(),
                    keri::event::sections::seal::Seal::Root(_) => todo!(),
                })
            }
            keri::event::event_data::EventData::Drt(_) => todo!(),
        }
        .is_none()
        {
            return Err(Error::MissingSealError);
        };

        let state = self
            .db
            .compute_management_tel_state(&event.data.prefix)?
            .unwrap_or_default();

        state.apply(&event)?;

        Ok(())
    }

    pub fn validate_vc(
        &self,
        vc_event: &VCEventMessage,
        seal: &AttachedSourceSeal,
    ) -> Result<(), Error> {
        self.db
            .compute_vc_state(&vc_event.data.data.prefix)?
            .unwrap_or_default()
            .apply(&vc_event)?;

        Ok(())
    }
}
