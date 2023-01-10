use keri::{prefix::IdentifierPrefix, sai::SelfAddressingPrefix};

use crate::{
    database::EventDatabase,
    error::Error,
    event::{verifiable_event::VerifiableEvent, Event},
    state::{vc_state::TelState, ManagerTelState, State},
};

pub struct EventProcessor<'d> {
    db: &'d EventDatabase,
}
impl<'d> EventProcessor<'d> {
    pub fn new(db: &'d EventDatabase) -> Self {
        Self { db }
    }

    pub fn get_management_tel_state(
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

    pub fn get_vc_state(&self, vc_id: &IdentifierPrefix) -> Result<TelState, Error> {
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

    // Process verifiable event. It doesn't check if source seal is correct. Just add event to tel.
    pub fn process(&self, event: VerifiableEvent) -> Result<State, Error> {
        match &event.event.clone() {
            Event::Management(ref man) => self
                .get_management_tel_state(&man.prefix)?
                .apply(man)
                .map(|state| {
                    self.db
                        .add_new_management_event(event, &man.prefix)
                        .unwrap();
                    State::Management(state)
                }),
            Event::Vc(ref vc_ev) => self.get_vc_state(&vc_ev.event.content.data.prefix)?.apply(vc_ev).map(|state| {
                self.db.add_new_event(event, &vc_ev.event.content.data.prefix).unwrap();
                State::Tel(state)
            }),
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

    pub fn get_events(&self, vc_id: &SelfAddressingPrefix) -> Result<Vec<VerifiableEvent>, Error> {
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
                    man.sn == sn
                } else {
                    false
                }
            })),
            None => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use keri::{prefix::IdentifierPrefix, sai::derivation::SelfAddressing};

    use crate::{
        error::Error, event::verifiable_event::VerifiableEvent, processor::EventProcessor,
        seal::EventSourceSeal, state::vc_state::TelState, tel::event_generator,
    };

    #[test]
    pub fn test_processing() -> Result<(), Error> {
        use std::fs;
        use tempfile::Builder;
        // Create test db and processor.
        let root = Builder::new().prefix("test-db").tempdir().unwrap();
        fs::create_dir_all(root.path()).unwrap();
        let db = crate::database::EventDatabase::new(root.path()).unwrap();
        let processor = EventProcessor::new(&db);

        // Setup test data.
        let message = "some message";
        let message_id = SelfAddressing::Blake3_256.derive(message.as_bytes());
        let issuer_prefix: IdentifierPrefix = "EaKJ0FoLxO1TYmyuprguKO7kJ7Hbn0m0Wuk5aMtSrMtY"
            .parse()
            .unwrap();
        let dummy_source_seal = EventSourceSeal {
            sn: 1,
            digest: "EJJR2nmwyYAfSVPzhzS6b5CMZAoTNZH3ULvaU6Z-i0d8"
                .parse()
                .unwrap(),
        };

        let vcp =
            event_generator::make_inception_event(issuer_prefix, vec![], 0, vec![], None, None)?;

        let management_tel_prefix = vcp.get_prefix();

        // before applying vcp to management tel, insert anchor event seal.
        // note: source seal isn't check while event processing.
        let verifiable_vcp = VerifiableEvent::new(vcp.clone(), dummy_source_seal.clone().into());
        processor.process(verifiable_vcp.clone())?;

        // Check management state.
        let st = processor.get_management_tel_state(&management_tel_prefix)?;
        assert_eq!(st.sn, 0);

        // check if vcp event is in db.
        let man_event_from_db = processor.get_management_event_at_sn(&management_tel_prefix, 0)?;
        assert!(man_event_from_db.is_some());
        assert_eq!(man_event_from_db.unwrap(), verifiable_vcp);

        // create issue event
        let vc_prefix = IdentifierPrefix::SelfAddressing(message_id.clone());
        let iss_event = event_generator::make_issuance_event(&st, message_id.clone(), None, None)?;

        let verifiable_iss =
            VerifiableEvent::new(iss_event.clone(), dummy_source_seal.clone().into());
        println!("\nbis: {}", String::from_utf8(verifiable_iss.clone().serialize().unwrap()).unwrap());
        processor.process(verifiable_iss.clone())?;

        // Chcek if iss event is in db.
        let o = processor.get_events(&message_id)?;
        assert_eq!(o[0].serialize().unwrap(), verifiable_iss.serialize().unwrap());

        let state =
            processor.get_vc_state(&IdentifierPrefix::SelfAddressing(message_id.clone()))?;
        assert!(matches!(state, TelState::Issued(_)));
        let last = match state {
            TelState::Issued(last) => Some(last),
            _ => None,
        };

        // Create revocation event.
        let rev_event = event_generator::make_revoke_event(&message_id, last.unwrap(), &st, None, None)?;

        let verifiable_rev =
            VerifiableEvent::new(rev_event.clone(), dummy_source_seal.clone().into());
        println!("\nbrv: {}", String::from_utf8(verifiable_rev.clone().serialize().unwrap()).unwrap());

        // Check if vc was revoked.
        processor.process(verifiable_rev.clone())?;
        let state = processor.get_vc_state(&vc_prefix)?;
        assert!(matches!(state, TelState::Revoked));

        // Chcek if rev event is in db.
        let o = processor.get_events(&message_id)?;
        assert_eq!(o.len(), 2);
        assert_eq!(
            o.iter().map(|e| e.serialize().unwrap()).collect::<Vec<_>>(), 
            vec![verifiable_iss, verifiable_rev].iter().map(|e| e.serialize().unwrap()).collect::<Vec<_>>()
        );

        let backers: Vec<IdentifierPrefix> = vec!["BwFbQvUaS4EirvZVPUav7R_KDHB8AKmSfXNpWnZU_YEU"
            .parse()
            .unwrap()];

        let vrt = event_generator::make_rotation_event(&st, &backers, &vec![], None, None)?;

        let verifiable_vrt = VerifiableEvent::new(vrt.clone(), dummy_source_seal.clone().into());
        processor.process(verifiable_vrt.clone())?;

        // Check management state.
        let st = processor.get_management_tel_state(&management_tel_prefix)?;
        assert_eq!(st.sn, 1);

        // check if vrt event is in db.
        let man_event_from_db = processor.get_management_event_at_sn(&management_tel_prefix, 1)?;
        assert!(man_event_from_db.is_some());
        assert_eq!(man_event_from_db.unwrap(), verifiable_vrt);

        Ok(())
    }
}
