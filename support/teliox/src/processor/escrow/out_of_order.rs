use std::{sync::Arc, time::Duration};

use keri::{
    database::escrow::{Escrow, EscrowDb},
    prefix::IdentifierPrefix,
    processor::event_storage::EventStorage,
};

use crate::{
    error::Error,
    event::verifiable_event::VerifiableEvent,
    processor::{
        notification::{TelNotification, TelNotificationBus, TelNotifier},
        storage::TelEventStorage,
        validator::TelEventValidator,
    },
};

pub struct OutOfOrderEscrow {
    tel_reference: Arc<TelEventStorage>,
    kel_reference: Arc<EventStorage>,
    escrowed_out_of_order: Escrow<VerifiableEvent>,
}

impl OutOfOrderEscrow {
    pub fn new(
        tel_reference: Arc<TelEventStorage>,
        kel_reference: Arc<EventStorage>,
        escrow_db: Arc<EscrowDb>,
        duration: Duration,
    ) -> Self {
        let escrow = Escrow::new(b"ooes", duration, escrow_db);
        Self {
            tel_reference,
            kel_reference,
            escrowed_out_of_order: escrow,
        }
    }
}

impl TelNotifier for OutOfOrderEscrow {
    fn notify(
        &self,
        notification: &TelNotification,
        bus: &TelNotificationBus,
    ) -> Result<(), Error> {
        match notification {
            TelNotification::OutOfOrder(signed_event) => {
                let key_id = signed_event.get_event().get_prefix();

                self.escrowed_out_of_order
                    .add(&key_id, signed_event.clone())
                    .map_err(|_e| Error::EscrowDatabaseError)
            }
            TelNotification::TelEventAdded(event) => {
                self.process_out_of_order_events(bus, &event.event.get_prefix())
            }
            _ => Err(Error::Generic("Wrong notification".into())),
        }
    }
}

impl OutOfOrderEscrow {
    pub fn process_out_of_order_events(
        &self,
        bus: &TelNotificationBus,
        id: &IdentifierPrefix,
    ) -> Result<(), Error> {
        if let Some(esc) = self.escrowed_out_of_order.get(id) {
            for event in esc {
                let validator = TelEventValidator::new(
                    self.tel_reference.db.clone(),
                    self.kel_reference.clone(),
                );
                match validator.validate(&event) {
                    Ok(_) => {
                        // remove from escrow
                        self.escrowed_out_of_order
                            .remove(id, &event)
                            .map_err(|_e| Error::EscrowDatabaseError)?;
                        // accept tel event
                        self.tel_reference.add_event(event.clone())?;

                        bus.notify(&TelNotification::TelEventAdded(event.clone()))?;
                        // stop processing the escrow if tel was updated. It needs to start again.
                        break;
                    }
                    Err(Error::MissingSealError) => {
                        // remove from escrow
                        self.escrowed_out_of_order.remove(id, &event).unwrap();
                    }
                    Err(_e) => {} // keep in escrow,
                }
            }
        };

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::{sync::Arc, time::Duration};

    use keri::{
        actor::parse_event_stream,
        database::{escrow::EscrowDb, SledEventDatabase},
        prefix::IdentifierPrefix,
        processor::{basic_processor::BasicProcessor, event_storage::EventStorage, Processor},
    };

    use crate::{
        database::EventDatabase,
        error::Error,
        event::verifiable_event::VerifiableEvent,
        processor::{
            escrow::out_of_order::OutOfOrderEscrow,
            notification::{TelNotificationBus, TelNotificationKind},
            TelEventProcessor, TelEventStorage,
        },
        state::vc_state::TelState,
    };

    #[test]
    pub fn test_out_of_order_escrow() -> Result<(), Error> {
        use tempfile::Builder;

        // Setup issuer key event log. Without ixn events tel event's can't be validated.
        let keri_root = Builder::new().prefix("test-db").tempdir().unwrap();
        let keri_db = Arc::new(SledEventDatabase::new(keri_root.path()).unwrap());
        let keri_processor = BasicProcessor::new(keri_db.clone(), None);
        let keri_storage = Arc::new(EventStorage::new(keri_db.clone()));

        let issuer_kel = r#"{"v":"KERI10JSON00012b_","t":"icp","d":"EPyhGnPEzI1OjbmvNCEsiQfinmwxGcJgyDK_Nx9hnI2l","i":"EPyhGnPEzI1OjbmvNCEsiQfinmwxGcJgyDK_Nx9hnI2l","s":"0","kt":"1","k":["DA11BfhLUT4Jvk-5vpyO3oADg0s09banjPsRTrh71nAq"],"nt":"1","n":["EPMnPDJ3lZ3xIj0YT61461pXa-NLbOsGCTDc5O7cfclL"],"bt":"0","b":[],"c":[],"a":[]}-AABAAAOJey_ELDDtz51QS-dSmh6EBg1S6NJGVweDIuwX6aka4ZjzjooPyz3OtZMMcesPAw2jfoFeg-hUR7iSH4tURkP{"v":"KERI10JSON00013a_","t":"ixn","d":"ENMILl_3-wbKmzOR5IC4rOjwwXE-LFafC34vzduBn2O1","i":"EPyhGnPEzI1OjbmvNCEsiQfinmwxGcJgyDK_Nx9hnI2l","s":"1","p":"EPyhGnPEzI1OjbmvNCEsiQfinmwxGcJgyDK_Nx9hnI2l","a":[{"i":"EPafIvNeW6xYZZhmXBO3hc3GtCHv-8jDgdZsKAFffhLN","s":"0","d":"EJPLd0ZMdbusC-nEQgXfVDcNWPkaZfhPAYH43ZqIrOOA"}]}-AABAABkcHE1DAkNFg7s8oRbtwx3ogkjhawBkKLL8KEZGRDh0lUKO9lx_zhs81NDWp5bfH26yExwRoD0bEdRIoolFt4L{"v":"KERI10JSON00013a_","t":"ixn","d":"EPBB-kmu3NQkuDUijczDscu6SMkOq_XznhufG2DFiveh","i":"EPyhGnPEzI1OjbmvNCEsiQfinmwxGcJgyDK_Nx9hnI2l","s":"2","p":"ENMILl_3-wbKmzOR5IC4rOjwwXE-LFafC34vzduBn2O1","a":[{"i":"EEvXZtq623byRrE7h34J7sosXnSlXT5oKMuvntyqTgVa","s":"0","d":"EH--8AOVXFyZ5HdshHVUjYIgrxqIRczzzbTZiZRzl6v8"}]}-AABAADPWrG2rkAJf0V1LoxMToz0ewXc6SiSTutM0CbMrVWNuoPJwc-2KrltNDRDAzCoJMlX23_l_vkpvOxb0_AnNtoC{"v":"KERI10JSON00013a_","t":"ixn","d":"EKtt7vosEnv-Y0QVRfZq5HFmRZ1e_l5NeJq-zq_wd2ht","i":"EPyhGnPEzI1OjbmvNCEsiQfinmwxGcJgyDK_Nx9hnI2l","s":"3","p":"EPBB-kmu3NQkuDUijczDscu6SMkOq_XznhufG2DFiveh","a":[{"i":"EEvXZtq623byRrE7h34J7sosXnSlXT5oKMuvntyqTgVa","s":"1","d":"EBr1rgUjzKeGKRijXUkc-Sx_LzB1HUxyd3qB6zc8Jaga"}]}-AABAADlK0LDw76SctNkrLZmcvncZ5IumaZi5cL0nPUZud5apxmTgJnSQ5SSTA7D4DJ5q7SG-5IL8uzYS4SMaT-uk8IG"#;

        let kel = parse_event_stream(issuer_kel.as_bytes())?;
        for event in kel {
            keri_processor.process(&event)?;
        }

        // Initiate tel and it's escrows
        let tel_root = Builder::new().prefix("test-db").tempdir().unwrap();
        let tel_escrow_root = Builder::new().prefix("test-db").tempdir().unwrap();
        let tel_events_db = Arc::new(EventDatabase::new(&tel_root.path()).unwrap());

        let tel_escrow_db = Arc::new(EscrowDb::new(&tel_escrow_root.path()).unwrap());

        let tel_storage = Arc::new(TelEventStorage::new(tel_events_db));
        let tel_bus = TelNotificationBus::new();

        let out_of_order_escrow = Arc::new(OutOfOrderEscrow::new(
            tel_storage.clone(),
            keri_storage.clone(),
            tel_escrow_db,
            Duration::from_secs(100),
        ));

        tel_bus.register_observer(
            out_of_order_escrow.clone(),
            vec![
                TelNotificationKind::OutOfOrder,
                TelNotificationKind::TelEventAdded,
            ],
        )?;

        let tel_events = r#"{"v":"KERI10JSON0000e0_","t":"vcp","d":"EJPLd0ZMdbusC-nEQgXfVDcNWPkaZfhPAYH43ZqIrOOA","i":"EPafIvNeW6xYZZhmXBO3hc3GtCHv-8jDgdZsKAFffhLN","s":"0","ii":"EPyhGnPEzI1OjbmvNCEsiQfinmwxGcJgyDK_Nx9hnI2l","c":["NB"],"bt":"0","b":[]}-GAB0AAAAAAAAAAAAAAAAAAAAAABENMILl_3-wbKmzOR5IC4rOjwwXE-LFafC34vzduBn2O1{"v":"KERI10JSON000162_","t":"bis","d":"EH--8AOVXFyZ5HdshHVUjYIgrxqIRczzzbTZiZRzl6v8","i":"EEvXZtq623byRrE7h34J7sosXnSlXT5oKMuvntyqTgVa","s":"0","ii":"EPyhGnPEzI1OjbmvNCEsiQfinmwxGcJgyDK_Nx9hnI2l","ra":{"i":"EPafIvNeW6xYZZhmXBO3hc3GtCHv-8jDgdZsKAFffhLN","s":"0","d":"EJPLd0ZMdbusC-nEQgXfVDcNWPkaZfhPAYH43ZqIrOOA"},"dt":"2023-06-30T08:04:23.180342+00:00"}-GAB0AAAAAAAAAAAAAAAAAAAAAACEPBB-kmu3NQkuDUijczDscu6SMkOq_XznhufG2DFiveh{"v":"KERI10JSON000161_","t":"brv","d":"EBr1rgUjzKeGKRijXUkc-Sx_LzB1HUxyd3qB6zc8Jaga","i":"EEvXZtq623byRrE7h34J7sosXnSlXT5oKMuvntyqTgVa","s":"1","p":"EH--8AOVXFyZ5HdshHVUjYIgrxqIRczzzbTZiZRzl6v8","ra":{"i":"EPafIvNeW6xYZZhmXBO3hc3GtCHv-8jDgdZsKAFffhLN","s":"0","d":"EJPLd0ZMdbusC-nEQgXfVDcNWPkaZfhPAYH43ZqIrOOA"},"dt":"2023-06-30T08:04:23.186687+00:00"}-GAB0AAAAAAAAAAAAAAAAAAAAAADEKtt7vosEnv-Y0QVRfZq5HFmRZ1e_l5NeJq-zq_wd2ht"#;
        let parsed_tel = VerifiableEvent::parse(tel_events.as_bytes())?;

        let vcp = parsed_tel[0].clone();
        let iss = parsed_tel[1].clone();
        let rev = parsed_tel[2].clone();

        let processor = TelEventProcessor::new(keri_storage, tel_storage.clone(), Some(tel_bus));
        // Incept registry
        processor.process(vcp)?;

        // Process out of order event.
        processor.process(rev)?;

        let vc_hash: IdentifierPrefix = "EEvXZtq623byRrE7h34J7sosXnSlXT5oKMuvntyqTgVa"
            .parse()
            .unwrap();

        // Check vc tel state. Iss event should't be accepted, because of
        // missing issuance event. It should be in out of order escrow.
        let st = tel_storage.compute_vc_state(&vc_hash)?;
        assert!(st.is_none());
        let st = tel_storage.compute_vc_state(&vc_hash)?;
        assert!(st.is_none());

        // Process missing event
        processor.process(iss)?;

        let st = tel_storage.compute_vc_state(&vc_hash)?;
        assert!(st.is_some());
        assert_eq!(TelState::Revoked, st.unwrap());

        Ok(())
    }
}
