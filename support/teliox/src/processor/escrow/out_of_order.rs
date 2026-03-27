use std::{sync::Arc, time::Duration};

use keri_core::{
    database::{
        redb::{escrow_database::SnKeyDatabase, WriteTxnMode},
        EventDatabase, SequencedEventDatabase,
    },
    prefix::IdentifierPrefix,
    processor::event_storage::EventStorage,
};

use crate::{
    database::{EscrowDatabase, TelEventDatabase, TelLogDatabase},
    error::Error,
    processor::{
        notification::{TelNotification, TelNotificationBus, TelNotifier},
        storage::TelEventStorage,
        validator::TelEventValidator,
    },
};

pub struct OutOfOrderEscrow<D: TelEventDatabase + TelLogDatabase, K: EventDatabase> {
    tel_reference: Arc<TelEventStorage<D>>,
    kel_reference: Arc<EventStorage<K>>,
    tel_log: Arc<D>,
    escrowed_out_of_order: SnKeyDatabase,
}

impl<D: TelEventDatabase + TelLogDatabase, K: EventDatabase> OutOfOrderEscrow<D, K> {
    pub fn new(
        tel_reference: Arc<D>,
        kel_reference: Arc<EventStorage<K>>,
        escrow_db: &EscrowDatabase,
        duration: Duration,
    ) -> Self {
        let escrow = SnKeyDatabase::new(escrow_db.0.clone(), "out_of_order").unwrap();
        let tel_event_storage = Arc::new(TelEventStorage::new(tel_reference.clone()));
        Self {
            tel_reference: tel_event_storage,
            kel_reference,
            escrowed_out_of_order: escrow,
            tel_log: tel_reference,
        }
    }
}

impl<D: TelEventDatabase + TelLogDatabase, K: EventDatabase> TelNotifier for OutOfOrderEscrow<D, K> {
    fn notify(
        &self,
        notification: &TelNotification,
        bus: &TelNotificationBus,
    ) -> Result<(), Error> {
        match notification {
            TelNotification::OutOfOrder(signed_event) => {
                let event = signed_event.get_event();
                let key_id = event.get_prefix();
                self.tel_log
                    .log_event(signed_event, &WriteTxnMode::CreateNew)?;
                let sn = event.get_sn();
                let digest = event.get_digest()?;

                self.escrowed_out_of_order
                    .insert(&key_id, sn, &digest)
                    .map_err(|e| Error::EscrowDatabaseError(e.to_string()))
            }
            TelNotification::TelEventAdded(event) => {
                let sn = event.get_event().get_sn();
                self.process_out_of_order_events(bus, &event.event.get_prefix(), sn)
            }
            _ => Err(Error::Generic("Wrong notification".into())),
        }
    }
}

impl<D: TelEventDatabase + TelLogDatabase, K: EventDatabase> OutOfOrderEscrow<D, K> {
    pub fn process_out_of_order_events(
        &self,
        bus: &TelNotificationBus,
        id: &IdentifierPrefix,
        sn: u64,
    ) -> Result<(), Error> {
        if let Ok(esc) = self.escrowed_out_of_order.get(id, sn + 1) {
            for said in esc {
                let event = self
                    .tel_log
                    .get(&said)
                    .map_err(|e| Error::EscrowDatabaseError(e.to_string()))?
                    .ok_or(Error::Generic(format!(
                        "Event of digest {} not found in out of order escrow",
                        said
                    )))?;
                let validator =
                    TelEventValidator::new(self.tel_reference.clone(), self.kel_reference.clone());
                match validator.validate(&event) {
                    Ok(_) => {
                        // remove from escrow
                        self.escrowed_out_of_order
                            .remove(id, sn, &said)
                            .map_err(|e| Error::EscrowDatabaseError(e.to_string()))?;
                        // accept tel event
                        self.tel_reference.add_event(event.clone())?;

                        bus.notify(&TelNotification::TelEventAdded(event.clone()))?;
                        // stop processing the escrow if tel was updated. It needs to start again.
                        break;
                    }
                    Err(Error::MissingSealError) => {
                        // remove from escrow
                        self.escrowed_out_of_order
                            .remove(id, sn, &said)
                            .map_err(|e| Error::EscrowDatabaseError(e.to_string()))?;
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

    use keri_core::{
        actor::parse_event_stream,
        database::redb::RedbDatabase,
        prefix::IdentifierPrefix,
        processor::{basic_processor::BasicProcessor, event_storage::EventStorage, Processor},
    };
    use redb::Database;

    use crate::{
        database::{redb::RedbTelDatabase, EscrowDatabase, TelEventDatabase},
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
        let keri_root = Builder::new().prefix("test-db").tempfile().unwrap();
        let keri_db = Arc::new(RedbDatabase::new(keri_root.path()).unwrap());
        let keri_processor = BasicProcessor::new(keri_db.clone(), None);
        let keri_storage = Arc::new(EventStorage::new(keri_db.clone()));

        let issuer_kel = r#"{"v":"KERI10JSON00012b_","t":"icp","d":"EPyhGnPEzI1OjbmvNCEsiQfinmwxGcJgyDK_Nx9hnI2l","i":"EPyhGnPEzI1OjbmvNCEsiQfinmwxGcJgyDK_Nx9hnI2l","s":"0","kt":"1","k":["DA11BfhLUT4Jvk-5vpyO3oADg0s09banjPsRTrh71nAq"],"nt":"1","n":["EPMnPDJ3lZ3xIj0YT61461pXa-NLbOsGCTDc5O7cfclL"],"bt":"0","b":[],"c":[],"a":[]}-AABAAAOJey_ELDDtz51QS-dSmh6EBg1S6NJGVweDIuwX6aka4ZjzjooPyz3OtZMMcesPAw2jfoFeg-hUR7iSH4tURkP{"v":"KERI10JSON00013a_","t":"ixn","d":"ENMILl_3-wbKmzOR5IC4rOjwwXE-LFafC34vzduBn2O1","i":"EPyhGnPEzI1OjbmvNCEsiQfinmwxGcJgyDK_Nx9hnI2l","s":"1","p":"EPyhGnPEzI1OjbmvNCEsiQfinmwxGcJgyDK_Nx9hnI2l","a":[{"i":"EPafIvNeW6xYZZhmXBO3hc3GtCHv-8jDgdZsKAFffhLN","s":"0","d":"EJPLd0ZMdbusC-nEQgXfVDcNWPkaZfhPAYH43ZqIrOOA"}]}-AABAABkcHE1DAkNFg7s8oRbtwx3ogkjhawBkKLL8KEZGRDh0lUKO9lx_zhs81NDWp5bfH26yExwRoD0bEdRIoolFt4L{"v":"KERI10JSON00013a_","t":"ixn","d":"EPBB-kmu3NQkuDUijczDscu6SMkOq_XznhufG2DFiveh","i":"EPyhGnPEzI1OjbmvNCEsiQfinmwxGcJgyDK_Nx9hnI2l","s":"2","p":"ENMILl_3-wbKmzOR5IC4rOjwwXE-LFafC34vzduBn2O1","a":[{"i":"EEvXZtq623byRrE7h34J7sosXnSlXT5oKMuvntyqTgVa","s":"0","d":"EH--8AOVXFyZ5HdshHVUjYIgrxqIRczzzbTZiZRzl6v8"}]}-AABAADPWrG2rkAJf0V1LoxMToz0ewXc6SiSTutM0CbMrVWNuoPJwc-2KrltNDRDAzCoJMlX23_l_vkpvOxb0_AnNtoC{"v":"KERI10JSON00013a_","t":"ixn","d":"EKtt7vosEnv-Y0QVRfZq5HFmRZ1e_l5NeJq-zq_wd2ht","i":"EPyhGnPEzI1OjbmvNCEsiQfinmwxGcJgyDK_Nx9hnI2l","s":"3","p":"EPBB-kmu3NQkuDUijczDscu6SMkOq_XznhufG2DFiveh","a":[{"i":"EEvXZtq623byRrE7h34J7sosXnSlXT5oKMuvntyqTgVa","s":"1","d":"EBr1rgUjzKeGKRijXUkc-Sx_LzB1HUxyd3qB6zc8Jaga"}]}-AABAADlK0LDw76SctNkrLZmcvncZ5IumaZi5cL0nPUZud5apxmTgJnSQ5SSTA7D4DJ5q7SG-5IL8uzYS4SMaT-uk8IG"#;

        let kel = parse_event_stream(issuer_kel.as_bytes()).unwrap();
        for event in kel {
            keri_processor.process(&event)?;
        }

        // Initiate tel and it's escrows
        let tel_root = Builder::new().prefix("test-db").tempfile().unwrap();
        let tel_escrow_root = Builder::new().prefix("test-db").tempfile().unwrap();
        let tel_events_db = Arc::new(RedbTelDatabase::new(&tel_root.path()).unwrap());

        let escrow_db = EscrowDatabase::new(&tel_escrow_root.path()).unwrap();

        let tel_storage = Arc::new(TelEventStorage::new(tel_events_db.clone()));
        let tel_bus = TelNotificationBus::new();

        let out_of_order_escrow = Arc::new(OutOfOrderEscrow::new(
            tel_events_db,
            keri_storage.clone(),
            &escrow_db,
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
