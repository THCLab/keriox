use std::{sync::Arc, time::Duration};

use keri_core::{
    database::{escrow::{Escrow, EscrowDb}, redb::RedbDatabase},
    prefix::IdentifierPrefix,
    processor::{
        event_storage::EventStorage,
        notification::{Notification, NotificationBus, Notifier},
    },
};

use crate::{
    error::Error,
    event::{verifiable_event::VerifiableEvent, Event},
    processor::{
        notification::{TelNotification, TelNotificationBus, TelNotifier},
        storage::TelEventStorage,
        validator::TelEventValidator,
    },
};

pub struct MissingIssuerEscrow {
    kel_reference: Arc<EventStorage<RedbDatabase>>,
    tel_reference: Arc<TelEventStorage>,
    publisher: TelNotificationBus,
    escrowed_missing_issuer: Escrow<VerifiableEvent>,
}

impl MissingIssuerEscrow {
    pub fn new(
        db: Arc<TelEventStorage>,
        escrow_db: Arc<EscrowDb>,
        duration: Duration,
        kel_reference: Arc<EventStorage<RedbDatabase>>,
        bus: TelNotificationBus,
    ) -> Self {
        let escrow = Escrow::new(b"mie.", duration, escrow_db);

        Self {
            tel_reference: db,
            escrowed_missing_issuer: escrow,
            kel_reference,
            publisher: bus,
        }
    }
}
impl Notifier for MissingIssuerEscrow {
    fn notify(
        &self,
        notification: &Notification,
        _bus: &NotificationBus,
    ) -> Result<(), keri_core::error::Error> {
        match notification {
            Notification::KeyEventAdded(ev_message) => {
                let digest = ev_message.event_message.digest()?;

                self.process_missing_issuer_escrow(&IdentifierPrefix::self_addressing(digest))
                    .unwrap();
            }
            _ => {
                return Err(keri_core::error::Error::SemanticError(
                    "Wrong notification".into(),
                ))
            }
        }

        Ok(())
    }
}

impl TelNotifier for MissingIssuerEscrow {
    fn notify(
        &self,
        notification: &TelNotification,
        _bus: &TelNotificationBus,
    ) -> Result<(), Error> {
        match notification {
            TelNotification::MissingIssuer(event) => {
                let missing_event_digest =
                    IdentifierPrefix::self_addressing(event.seal.seal.digest.clone());
                self.escrowed_missing_issuer
                    .add(&missing_event_digest, event.clone())
                    .map_err(|_e| Error::EscrowDatabaseError)
            }
            _ => return Err(Error::Generic("Wrong notification".into())),
        }
    }
}

impl MissingIssuerEscrow {
    /// Reprocess escrowed events that need issuer event of given digest for acceptance.
    pub fn process_missing_issuer_escrow(&self, id: &IdentifierPrefix) -> Result<(), Error> {
        if let Some(esc) = self.escrowed_missing_issuer.get(id) {
            for event in esc {
                let validator = TelEventValidator::new(
                    self.tel_reference.db.clone(),
                    self.kel_reference.clone(),
                );
                let result = match &event.event {
                    Event::Management(man) => validator.validate_management(&man, &event.seal),
                    Event::Vc(vc) => validator.validate_vc(&vc, &event.seal),
                };
                match result {
                    Ok(_) => {
                        // remove from escrow
                        self.escrowed_missing_issuer
                            .remove(id, &event)
                            .map_err(|_e| Error::EscrowDatabaseError)?;
                        // accept tel event
                        self.tel_reference.add_event(event.clone())?;

                        self.publisher
                            .notify(&TelNotification::TelEventAdded(event))?;
                    }
                    Err(Error::MissingSealError) => {
                        // remove from escrow
                        self.escrowed_missing_issuer.remove(id, &event).unwrap();
                    }
                    Err(Error::OutOfOrderError) => {
                        self.escrowed_missing_issuer.remove(id, &event).unwrap();
                        self.publisher.notify(&TelNotification::OutOfOrder(event))?;
                    }
                    Err(Error::MissingRegistryError) => {
                        self.escrowed_missing_issuer.remove(id, &event).unwrap();
                        self.publisher
                            .notify(&TelNotification::MissingRegistry(event))?;
                    }
                    Err(_e) => (), // keep in escrow,
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
        database::{escrow::EscrowDb, redb::RedbDatabase, sled::SledEventDatabase},
        prefix::IdentifierPrefix,
        processor::{
            basic_processor::BasicProcessor, event_storage::EventStorage,
            notification::JustNotification, Processor,
        },
    };

    use crate::{
        database::EventDatabase,
        error::Error,
        event::{manager_event, verifiable_event::VerifiableEvent},
        processor::{
            escrow::missing_issuer::MissingIssuerEscrow,
            notification::{TelNotificationBus, TelNotificationKind},
            TelEventProcessor, TelEventStorage,
        },
        seal::EventSourceSeal,
        tel::event_generator,
    };

    #[test]
    pub fn test_missing_issuer_escrow() -> Result<(), Error> {
        use tempfile::Builder;

        // Setup issuer key event log. Without ixn events tel event's can't be validated.
        let keri_root = Builder::new().prefix("test-db").tempfile().unwrap();
        let keri_db = Arc::new(RedbDatabase::new(keri_root.path()).unwrap());
        let escrow_root = Builder::new().prefix("test-db").tempdir().unwrap();
        let escrow_db = Arc::new(SledEventDatabase::new(escrow_root.path()).unwrap());
        let mut keri_processor = BasicProcessor::new(keri_db.clone(), escrow_db.clone(), None);
        let keri_storage = Arc::new(EventStorage::new(keri_db.clone(), escrow_db));

        let issuer_kel = r#"{"v":"KERI10JSON00012b_","t":"icp","d":"EETk5xW-rl2TgHTTXr8m5kGXiC30m3gMgsYcBAjOE9eI","i":"EETk5xW-rl2TgHTTXr8m5kGXiC30m3gMgsYcBAjOE9eI","s":"0","kt":"1","k":["DHdoiqT1iac2HI6-HfCYcc01Piz2FTTPvZDFt6vADioD"],"nt":"1","n":["EH8IzIWeQFiUr3rr2dh8xAiW9Akwl6EooDt8iduQYyq_"],"bt":"0","b":[],"c":[],"a":[]}-AABAABvFFeXb9uW2G16o3C9xJZvY3a_utMPxd4NIUcGWRTqykMO1NzKwjsA_AQrOEwgO5jselWHREcK6vcAxRfv6-QC{"v":"KERI10JSON00013a_","t":"ixn","d":"EMOzEVoFjbkS3ZS5JtmJO4LeZ4gydbr8iXNrEQAt1OR2","i":"EETk5xW-rl2TgHTTXr8m5kGXiC30m3gMgsYcBAjOE9eI","s":"1","p":"EETk5xW-rl2TgHTTXr8m5kGXiC30m3gMgsYcBAjOE9eI","a":[{"i":"EF3TVac5quxrbLGLKAHF21laISjMgjYQAIg3OsTen969","s":"0","d":"ENIKpuUkjM-1K2Sv_TZwF_k8FTVkefAgy8sIpiFp0uWh"}]}-AABAACvrSS_EZUMKQ6Ax8FaB_Sf99O0y6MmfoRDBKMphVWWtuCOlFQm6N0XrTwtYxO3pO0AEZkJ1vzu52-RDK-w3YAN{"v":"KERI10JSON00013a_","t":"ixn","d":"EDvnfU2yMZUXEy9D_22YOkeSZOq6YG9zfItawvx3GR_6","i":"EETk5xW-rl2TgHTTXr8m5kGXiC30m3gMgsYcBAjOE9eI","s":"2","p":"EMOzEVoFjbkS3ZS5JtmJO4LeZ4gydbr8iXNrEQAt1OR2","a":[{"i":"EC8Oej-3HAUpBY_kxzBK3B-0RV9j4dXw1H0NRKxJg7g-","s":"0","d":"EDBM1ys50vEJxRzvBjTOrmOhokELjVtozXy3ZbJ8-KFk"}]}-AABAAABtEQ7SoGt2IcZBMX0GaEaMqGdMsrGpj1fABDKgE5dA7s7AGXTkWrZjzA4GXkGXuOspi6upqBhpxr6d5ySeKQH"#;

        let kel = parse_event_stream(issuer_kel.as_bytes()).unwrap();
        let issuer_icp = kel[0].clone();
        let issuer_vcp_ixn = kel[1].clone();

        // Incept identifier
        keri_processor.process(&issuer_icp)?;

        // Initiate tel and it's escrows
        let tel_root = Builder::new().prefix("test-db").tempdir().unwrap();
        let tel_escrow_root = Builder::new().prefix("test-db").tempdir().unwrap();
        let tel_events_db = Arc::new(EventDatabase::new(&tel_root.path()).unwrap());

        let tel_escrow_db = Arc::new(EscrowDb::new(&tel_escrow_root.path()).unwrap());

        let tel_storage = Arc::new(TelEventStorage::new(tel_events_db));
        let tel_bus = TelNotificationBus::new();

        let missing_issuer_escrow = Arc::new(MissingIssuerEscrow::new(
            tel_storage.clone(),
            tel_escrow_db,
            Duration::from_secs(100),
            keri_storage.clone(),
            tel_bus.clone(),
        ));

        tel_bus.register_observer(
            missing_issuer_escrow.clone(),
            vec![TelNotificationKind::MissingIssuer],
        )?;

        keri_processor.register_observer(
            missing_issuer_escrow.clone(),
            &vec![JustNotification::KeyEventAdded],
        )?;

        let processor = TelEventProcessor::new(keri_storage, tel_storage.clone(), Some(tel_bus)); // TelEventProcessor{database: TelEventDatabase::new(db, db_escrow)};

        let issuer_prefix: IdentifierPrefix = "EETk5xW-rl2TgHTTXr8m5kGXiC30m3gMgsYcBAjOE9eI"
            .parse()
            .unwrap();
        let dummy_source_seal = EventSourceSeal {
            sn: 1,
            digest: "EMOzEVoFjbkS3ZS5JtmJO4LeZ4gydbr8iXNrEQAt1OR2"
                .parse()
                .unwrap(),
        };

        let vcp = event_generator::make_inception_event(
            issuer_prefix,
            vec![manager_event::Config::NoBackers],
            0,
            vec![],
            None,
            None,
        )?;

        let management_tel_prefix = vcp.get_prefix();

        // before applying vcp to management tel, insert anchor event seal with proper ixn event data.
        let verifiable_vcp = VerifiableEvent::new(vcp.clone(), dummy_source_seal.clone().into());
        processor.process(verifiable_vcp.clone())?;

        // Check management state. Vcp event should't be accepted, because of
        // missing issuer event. It should be in missing issuer escrow.
        let st = tel_storage.compute_management_tel_state(&management_tel_prefix)?;
        assert_eq!(st, None);

        // check if vcp event is in db.
        let man_event_from_db =
            tel_storage.get_management_event_at_sn(&management_tel_prefix, 0)?;
        assert!(man_event_from_db.is_none());

        // Process missing ixn in issuer's kel. Now escrowed vcp event should be
        // accepted.
        keri_processor.process(&issuer_vcp_ixn)?;

        let management_state = tel_storage
            .compute_management_tel_state(&management_tel_prefix)?
            .unwrap();
        assert_eq!(management_state.sn, 0);

        // check if vcp event is in db.
        let man_event_from_db =
            tel_storage.get_management_event_at_sn(&management_tel_prefix, 0)?;
        assert!(man_event_from_db.is_some());
        assert_eq!(
            man_event_from_db.unwrap().serialize().unwrap(),
            verifiable_vcp.serialize().unwrap()
        );

        Ok(())
    }
}
