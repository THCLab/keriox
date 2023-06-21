use std::sync::Arc;

use crate::{
    database::EventDatabase,
    error::Error,
    event::manager_event::Config,
    event::verifiable_event::VerifiableEvent,
    event::Event,
    processor::TelEventProcessor,
    state::{vc_state::TelState, ManagerTelState, State},
};
use keri::{
    database::escrow::EscrowDb, prefix::IdentifierPrefix, processor::event_storage::EventStorage,
};
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
    pub fn new(db: Arc<EventDatabase>, kel_reference: Arc<EventStorage>) -> Self {
        Self {
            processor: TelEventProcessor::new(kel_reference, db),
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
        ba: &[IdentifierPrefix],
        br: &[IdentifierPrefix],
    ) -> Result<Event, Error> {
        event_generator::make_rotation_event(&self.get_management_tel_state()?, ba, br, None, None)
    }

    pub fn make_issuance_event(
        &self,
        derivation: HashFunctionCode,
        vc: &str,
    ) -> Result<Event, Error> {
        let vc_hash = HashFunction::from(derivation).derive(vc.as_bytes());
        event_generator::make_issuance_event(&self.get_management_tel_state()?, vc_hash, None, None)
    }

    pub fn make_revoke_event(&self, vc: &SelfAddressingIdentifier) -> Result<Event, Error> {
        let vc_state = self.get_vc_state(vc)?;
        let last = match vc_state {
            TelState::Issued(last) => last,
            _ => return Err(Error::Generic("Inproper vc state".into())),
        };
        event_generator::make_revoke_event(vc, last, &self.get_management_tel_state()?, None, None)
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

    pub fn get_vc_state(&self, vc_hash: &SelfAddressingIdentifier) -> Result<TelState, Error> {
        let vc_prefix = IdentifierPrefix::SelfAddressing(vc_hash.to_owned());
        self.processor.tel_reference.compute_vc_state(&vc_prefix)
    }

    pub fn get_tel(
        &self,
        vc_hash: &SelfAddressingIdentifier,
    ) -> Result<Vec<VerifiableEvent>, Error> {
        self.processor.tel_reference.get_events(vc_hash)
    }

    pub fn get_management_tel_state(&self) -> Result<ManagerTelState, Error> {
        self.processor
            .tel_reference
            .compute_management_tel_state(&self.tel_prefix)
    }
}
#[cfg(test)]
mod tests {
    use std::{fs, sync::Arc};

    use keri::{
        database::{escrow::EscrowDb, SledEventDatabase},
        processor::event_storage::EventStorage,
    };

    use crate::{
        error::Error, event::verifiable_event::VerifiableEvent, seal::EventSourceSeal,
        state::State, tel::Tel,
    };

    #[test]
    pub fn test_management_tel() -> Result<(), Error> {
        use tempfile::Builder;
        let root = Builder::new().prefix("test-db1").tempdir().unwrap();
        std::fs::create_dir_all(root.path()).unwrap();
        let db_controller = Arc::new(SledEventDatabase::new(root.path()).unwrap());
        let kel_reference = Arc::new(EventStorage::new(db_controller));

        let tel_root = Builder::new().prefix("tel-test-db").tempdir().unwrap();
        let tel_root_db = Builder::new().prefix("tel-test-db").tempdir().unwrap();
        fs::create_dir_all(tel_root.path()).unwrap();
        let tel_db = Arc::new(crate::database::EventDatabase::new(tel_root.path()).unwrap());
        // let tel_db_escrow = Arc::new(EscrowDb::new(tel_root.path()).unwrap());
        let issuer_prefix = "DpE03it33djytuVvXhSbZdEw0lx7Xa-olrlUUSH2Ykvc"
            .parse()
            .unwrap();

        // Create tel
        let mut tel = Tel::new(tel_db, kel_reference);
        let dummy_source_seal = EventSourceSeal {
            sn: 1,
            digest: "EJJR2nmwyYAfSVPzhzS6b5CMZAoTNZH3ULvaU6Z-i0d8"
                .parse()
                .unwrap(),
        };

        let vcp = tel.make_inception_event(issuer_prefix, vec![], 0, vec![])?;
        let verifiable_vcp = VerifiableEvent::new(vcp.clone(), dummy_source_seal.clone().into());
        let processing_output = tel.process(verifiable_vcp.clone());
        assert!(processing_output.is_ok());

        let backers_to_add = vec!["EJJR2nmwyYAfSVPzhzS6b5CMZAoTNZH3ULvaU6Z-i0d8"
            .parse()
            .unwrap()];
        let rcp = tel.make_rotation_event(&backers_to_add, &vec![])?;
        let verifiable_rcp = VerifiableEvent::new(rcp.clone(), dummy_source_seal.into());
        let processing_output = tel.process(verifiable_rcp.clone());
        assert!(processing_output.is_ok());
        let state = tel.get_management_tel_state()?;
        assert_eq!(state.backers, Some(backers_to_add));

        Ok(())
    }
}
