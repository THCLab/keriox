use crate::{
    database::EventDatabase,
    error::Error,
    event::manager_event::Config,
    event::verifiable_event::VerifiableEvent,
    event::Event,
    processor::EventProcessor,
    state::{vc_state::TelState, ManagerTelState, State},
};
use keri::prefix::IdentifierPrefix;
use sai::{derivation::SelfAddressing, SelfAddressingPrefix};

pub mod event_generator;

/// Transaction Event Log
pub struct Tel<'d> {
    pub processor: EventProcessor<'d>,
    tel_prefix: IdentifierPrefix,
}

impl<'d> Tel<'d> {
    pub fn new(db: &'d EventDatabase) -> Self {
        Self {
            processor: EventProcessor::new(db),
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
        derivation: SelfAddressing,
        vc: &str,
    ) -> Result<Event, Error> {
        let vc_hash = derivation.derive(vc.as_bytes());
        event_generator::make_issuance_event(&self.get_management_tel_state()?, vc_hash, None, None)
    }

    pub fn make_revoke_event(&self, vc: &SelfAddressingPrefix) -> Result<Event, Error> {
        let vc_state = self.get_vc_state(vc)?;
        let last = match vc_state {
            TelState::Issued(last) => last,
            _ => return Err(Error::Generic("Inproper vc state".into())),
        };
        event_generator::make_revoke_event(vc, last, &self.get_management_tel_state()?, None, None)
    }

    // Process verifiable event. It doesn't check if source seal is correct. Just add event to tel.
    pub fn process(&mut self, event: VerifiableEvent) -> Result<State, Error> {
        let state = self.processor.process(event)?;
        // If tel prefix is not set yet, set it to first processed management event identifier prefix.
        if self.tel_prefix == IdentifierPrefix::default() {
            if let State::Management(ref man) = state {
                self.tel_prefix = man.prefix.to_owned()
            }
        }
        Ok(state)
    }

    pub fn get_vc_state(&self, vc_hash: &SelfAddressingPrefix) -> Result<TelState, Error> {
        let vc_prefix = IdentifierPrefix::SelfAddressing(vc_hash.to_owned());
        self.processor.get_vc_state(&vc_prefix)
    }

    pub fn get_tel(&self, vc_hash: &SelfAddressingPrefix) -> Result<Vec<VerifiableEvent>, Error> {
        self.processor.get_events(vc_hash)
    }

    pub fn get_management_tel_state(&self) -> Result<ManagerTelState, Error> {
        self.processor.get_management_tel_state(&self.tel_prefix)
    }
}
#[cfg(test)]
mod tests {
    use std::fs;

    use crate::{
        error::Error, event::verifiable_event::VerifiableEvent, seal::EventSourceSeal,
        state::State, tel::Tel,
    };

    #[test]
    pub fn test_management_tel() -> Result<(), Error> {
        use tempfile::Builder;

        let tel_root = Builder::new().prefix("tel-test-db").tempdir().unwrap();
        fs::create_dir_all(tel_root.path()).unwrap();
        let tel_db = crate::database::EventDatabase::new(tel_root.path()).unwrap();
        let issuer_prefix = "DpE03it33djytuVvXhSbZdEw0lx7Xa-olrlUUSH2Ykvc"
            .parse()
            .unwrap();

        // Create tel
        let mut tel = Tel::new(&tel_db);
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
        if let State::Management(man) = processing_output.unwrap() {
            assert_eq!(man.backers, Some(backers_to_add))
        }

        Ok(())
    }
}
