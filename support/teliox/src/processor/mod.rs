use std::sync::Arc;

use keri::processor::event_storage::EventStorage;

use crate::{
    database::EventDatabase,
    error::Error,
    event::{verifiable_event::VerifiableEvent, Event},
};

use self::{storage::TelEventStorage, validator::TelEventValidator};

pub mod escrow;
pub mod storage;
pub mod validator;

pub struct TelEventProcessor {
    kel_reference: Arc<EventStorage>,
    pub tel_reference: TelEventStorage,
}

impl TelEventProcessor {
    pub fn new(kel_reference: Arc<EventStorage>, db: Arc<EventDatabase>) -> Self {
        Self {
            kel_reference,
            tel_reference: TelEventStorage { db },
        }
    }
    // Process verifiable event. It doesn't check if source seal is correct. Just add event to tel.
    pub fn process(&self, event: VerifiableEvent) -> Result<(), Error> {
        let validator =
            TelEventValidator::new(self.tel_reference.db.clone(), self.kel_reference.clone());
        match &event.event.clone() {
            Event::Management(ref man) => match validator.validate_management(&man, &event.seal) {
                Ok(_) => {
                    self.tel_reference
                        .db
                        .add_new_management_event(event, &man.data.prefix)
                        .unwrap();
                    Ok(())
                }
                Err(e) => match e {
                    Error::DynError(_) => todo!(),
                    Error::KeriError(_) => todo!(),
                    Error::SledError(_) => todo!(),
                    Error::SledTablesError(_) => todo!(),
                    Error::Generic(_) => todo!(),
                    Error::VersionError(_) => todo!(),
                    Error::MissingSealError => todo!(),
                    Error::OutOfOrderError => todo!(),
                    Error::MissingIssuerEventError => todo!(),
                    Error::DigestsNotMatchError => todo!(),
                },
            },
            Event::Vc(ref vc_ev) => match validator.validate_vc(&vc_ev, &event.seal) {
                Ok(_) => {
                    self.tel_reference
                        .db
                        .add_new_event(event, &vc_ev.data.data.prefix)
                        .unwrap();
                    Ok(())
                }
                Err(_) => todo!(),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use keri::{database::escrow::EscrowDb, prefix::IdentifierPrefix};
    use said::derivation::{HashFunction, HashFunctionCode};

    use crate::{
        error::Error,
        event::verifiable_event::VerifiableEvent,
        processor::{TelEventProcessor, TelEventStorage},
        seal::EventSourceSeal,
        state::vc_state::TelState,
        tel::event_generator,
    };

    //     #[test]
    //     pub fn test_processing() -> Result<(), Error> {
    //         use std::fs;
    //         use tempfile::Builder;
    //         // Create test db and processor.
    //         let root = Builder::new().prefix("test-db").tempdir().unwrap();
    //         let root1 = Builder::new().prefix("test-db-1").tempdir().unwrap();
    //         fs::create_dir_all(root.path()).unwrap();
    //         let db = Arc::new(crate::database::EventDatabase::new(root.path()).unwrap());
    //         let db_escrow = Arc::new(EscrowDb::new(root1.path()).unwrap());
    //         let processor = TelEventProcessor{database: TelEventDatabase::new(db, db_escrow)};

    //         // Setup test data.
    //         let message = "some message";
    //         let message_id =
    //             HashFunction::from(HashFunctionCode::Blake3_256).derive(message.as_bytes());
    //         let issuer_prefix: IdentifierPrefix = "EaKJ0FoLxO1TYmyuprguKO7kJ7Hbn0m0Wuk5aMtSrMtY"
    //             .parse()
    //             .unwrap();
    //         let dummy_source_seal = EventSourceSeal {
    //             sn: 1,
    //             digest: "EJJR2nmwyYAfSVPzhzS6b5CMZAoTNZH3ULvaU6Z-i0d8"
    //                 .parse()
    //                 .unwrap(),
    //         };

    //         let vcp =
    //             event_generator::make_inception_event(issuer_prefix, vec![], 0, vec![], None, None)?;

    //         let management_tel_prefix = vcp.get_prefix();

    //         // before applying vcp to management tel, insert anchor event seal.
    //         // note: source seal isn't check while event processing.
    //         let verifiable_vcp = VerifiableEvent::new(vcp.clone(), dummy_source_seal.clone().into());
    //         processor.process(verifiable_vcp.clone())?;

    //         // Check management state.
    //         let st = processor.compute_management_tel_state(&management_tel_prefix)?;
    //         assert_eq!(st.sn, 0);

    //         // check if vcp event is in db.
    //         let man_event_from_db = processor.get_management_event_at_sn(&management_tel_prefix, 0)?;
    //         assert!(man_event_from_db.is_some());
    //         assert_eq!(
    //             man_event_from_db.unwrap().serialize().unwrap(),
    //             verifiable_vcp.serialize().unwrap()
    //         );

    //         // create issue event
    //         let vc_prefix = IdentifierPrefix::SelfAddressing(message_id.clone());
    //         let iss_event = event_generator::make_issuance_event(&st, message_id.clone(), None, None)?;

    //         let verifiable_iss =
    //             VerifiableEvent::new(iss_event.clone(), dummy_source_seal.clone().into());
    //         processor.process(verifiable_iss.clone())?;

    //         // Chcek if iss event is in db.
    //         let o = processor.get_events(&message_id)?;
    //         assert_eq!(
    //             o[0].serialize().unwrap(),
    //             verifiable_iss.serialize().unwrap()
    //         );

    //         let state =
    //             processor.compute_vc_state(&IdentifierPrefix::SelfAddressing(message_id.clone()))?;
    //         assert!(matches!(state, TelState::Issued(_)));
    //         let last = match state {
    //             TelState::Issued(last) => Some(last),
    //             _ => None,
    //         };

    //         // Create revocation event.
    //         let rev_event =
    //             event_generator::make_revoke_event(&message_id, last.unwrap(), &st, None, None)?;

    //         let verifiable_rev =
    //             VerifiableEvent::new(rev_event.clone(), dummy_source_seal.clone().into());

    //         // Check if vc was revoked.
    //         processor.process(verifiable_rev.clone())?;
    //         let state = processor.compute_vc_state(&vc_prefix)?;
    //         assert!(matches!(state, TelState::Revoked));

    //         // Chcek if rev event is in db.
    //         let o = processor.get_events(&message_id)?;
    //         assert_eq!(o.len(), 2);
    //         assert_eq!(
    //             o.iter().map(|e| e.serialize().unwrap()).collect::<Vec<_>>(),
    //             vec![verifiable_iss, verifiable_rev]
    //                 .iter()
    //                 .map(|e| e.serialize().unwrap())
    //                 .collect::<Vec<_>>()
    //         );

    //         let backers: Vec<IdentifierPrefix> = vec!["BwFbQvUaS4EirvZVPUav7R_KDHB8AKmSfXNpWnZU_YEU"
    //             .parse()
    //             .unwrap()];

    //         let vrt = event_generator::make_rotation_event(&st, &backers, &vec![], None, None)?;

    //         let verifiable_vrt = VerifiableEvent::new(vrt.clone(), dummy_source_seal.clone().into());
    //         processor.process(verifiable_vrt.clone())?;

    //         // Check management state.
    //         let st = processor.compute_management_tel_state(&management_tel_prefix)?;
    //         assert_eq!(st.sn, 1);

    //         // check if vrt event is in db.
    //         let man_event_from_db = processor.get_management_event_at_sn(&management_tel_prefix, 1)?;
    //         assert!(man_event_from_db.is_some());
    //         assert_eq!(
    //             man_event_from_db.unwrap().serialize().unwrap(),
    //             verifiable_vrt.serialize().unwrap()
    //         );

    //         Ok(())
    //     }
}
