use std::{sync::Arc, time::Duration};

use keri_core::{
    database::EventDatabase,
    processor::{
        event_storage::EventStorage,
        notification::{Notification, NotificationBus, Notifier},
    },
};
use said::SelfAddressingIdentifier;

use crate::{
    database::{TelEscrowDatabase, TelEventDatabase},
    error::Error,
    event::Event,
    processor::{
        notification::{TelNotification, TelNotificationBus, TelNotifier},
        storage::TelEventStorage,
        validator::TelEventValidator,
    },
};

pub struct MissingIssuerEscrow<D: TelEventDatabase, K: EventDatabase, E: TelEscrowDatabase> {
    kel_reference: Arc<EventStorage<K>>,
    tel_reference: Arc<TelEventStorage<D>>,
    publisher: TelNotificationBus,
    escrow_db: Arc<E>,
}

impl<D: TelEventDatabase, K: EventDatabase, E: TelEscrowDatabase>
    MissingIssuerEscrow<D, K, E>
{
    pub fn new(
        db: Arc<D>,
        escrow_db: Arc<E>,
        _duration: Duration,
        kel_reference: Arc<EventStorage<K>>,
        bus: TelNotificationBus,
    ) -> Self {
        let tel_event_storage = Arc::new(TelEventStorage::new(db));
        Self {
            tel_reference: tel_event_storage,
            escrow_db,
            kel_reference,
            publisher: bus,
        }
    }
}

impl<D: TelEventDatabase, K: EventDatabase, E: TelEscrowDatabase> Notifier
    for MissingIssuerEscrow<D, K, E>
{
    fn notify(
        &self,
        notification: &Notification,
        _bus: &NotificationBus,
    ) -> Result<(), keri_core::error::Error> {
        match notification {
            Notification::KeyEventAdded(ev_message) => {
                let digest = ev_message.event_message.digest()?;
                self.process_missing_issuer_escrow(&digest).unwrap();
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

impl<D: TelEventDatabase, K: EventDatabase, E: TelEscrowDatabase> TelNotifier
    for MissingIssuerEscrow<D, K, E>
{
    fn notify(
        &self,
        notification: &TelNotification,
        _bus: &TelNotificationBus,
    ) -> Result<(), Error> {
        match notification {
            TelNotification::MissingIssuer(event) => {
                let tel_event_digest = event.event.get_digest()?;
                self.tel_reference.db.log_event(event)?;
                let missing_event_digest = event.seal.seal.digest.clone().to_string();
                self.escrow_db
                    .missing_issuer_insert(&missing_event_digest, &tel_event_digest)
                    .map_err(|e| Error::EscrowDatabaseError(e.to_string()))
            }
            _ => return Err(Error::Generic("Wrong notification".into())),
        }
    }
}

impl<D: TelEventDatabase, K: EventDatabase, E: TelEscrowDatabase>
    MissingIssuerEscrow<D, K, E>
{
    pub fn process_missing_issuer_escrow(
        &self,
        said: &SelfAddressingIdentifier,
    ) -> Result<(), Error> {
        if let Ok(esc) = self.escrow_db.missing_issuer_get(&said.to_string()) {
            for digest in esc {
                let event = self.tel_reference.db.get_event(&digest)?.unwrap();
                let kel_event_digest = event.event.get_digest()?;
                let validator =
                    TelEventValidator::new(self.tel_reference.clone(), self.kel_reference.clone());
                let result = match &event.event {
                    Event::Management(man) => validator.validate_management(&man, &event.seal),
                    Event::Vc(vc) => validator.validate_vc(&vc, &event.seal),
                };
                match result {
                    Ok(_) => {
                        self.escrow_db
                            .missing_issuer_remove(&said.to_string(), &event.event.get_digest()?)
                            .map_err(|e| Error::EscrowDatabaseError(e.to_string()))?;
                        self.tel_reference.add_event(event.clone())?;
                        self.publisher
                            .notify(&TelNotification::TelEventAdded(event))?;
                    }
                    Err(Error::MissingSealError) => {
                        self.escrow_db
                            .missing_issuer_remove(&said.to_string(), &kel_event_digest)
                            .unwrap();
                    }
                    Err(Error::OutOfOrderError) => {
                        self.escrow_db
                            .missing_issuer_remove(&said.to_string(), &kel_event_digest)
                            .unwrap();
                        self.publisher.notify(&TelNotification::OutOfOrder(event))?;
                    }
                    Err(Error::MissingRegistryError) => {
                        self.escrow_db
                            .missing_issuer_remove(&said.to_string(), &kel_event_digest)
                            .unwrap();
                        self.publisher
                            .notify(&TelNotification::MissingRegistry(event))?;
                    }
                    Err(_e) => (),
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
        processor::{
            basic_processor::BasicProcessor, event_storage::EventStorage,
            notification::JustNotification, Processor,
        },
    };

    use crate::{
        database::{redb::RedbTelDatabase, EscrowDatabase},
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

        let keri_root = Builder::new().prefix("test-db").tempfile().unwrap();
        let keri_db = Arc::new(RedbDatabase::new(keri_root.path()).unwrap());
        let mut keri_processor = BasicProcessor::new(keri_db.clone(), None);
        let keri_storage = Arc::new(EventStorage::new(keri_db.clone()));

        let issuer_kel = r#"{"v":"KERI10JSON00012b_","t":"icp","d":"EETk5xW-rl2TgHTTXr8m5kGXiC30m3gMgsYcBAjOE9eI","i":"EETk5xW-rl2TgHTTXr8m5kGXiC30m3gMgsYcBAjOE9eI","s":"0","kt":"1","k":["DHdoiqT1iac2HI6-HfCYcc01Piz2FTTPvZDFt6vADioD"],"nt":"1","n":["EH8IzIWeQFiUr3rr2dh8xAiW9Akwl6EooDt8iduQYyq_"],"bt":"0","b":[],"c":[],"a":[]}-AABAABvFFeXb9uW2G16o3C9xJZvY3a_utMPxd4NIUcGWRTqykMO1NzKwjsA_AQrOEwgO5jselWHREcK6vcAxRfv6-QC{"v":"KERI10JSON00013a_","t":"ixn","d":"EMOzEVoFjbkS3ZS5JtmJO4LeZ4gydbr8iXNrEQAt1OR2","i":"EETk5xW-rl2TgHTTXr8m5kGXiC30m3gMgsYcBAjOE9eI","s":"1","p":"EETk5xW-rl2TgHTTXr8m5kGXiC30m3gMgsYcBAjOE9eI","a":[{"i":"EF3TVac5quxrbLGLKAHF21laISjMgjYQAIg3OsTen969","s":"0","d":"ENIKpuUkjM-1K2Sv_TZwF_k8FTVkefAgy8sIpiFp0uWh"}]}-AABAACvrSS_EZUMKQ6Ax8FaB_Sf99O0y6MmfoRDBKMphVWWtuCOlFQm6N0XrTwtYxO3pO0AEZkJ1vzu52-RDK-w3YAN{"v":"KERI10JSON00013a_","t":"ixn","d":"EDvnfU2yMZUXEy9D_22YOkeSZOq6YG9zfItawvx3GR_6","i":"EETk5xW-rl2TgHTTXr8m5kGXiC30m3gMgsYcBAjOE9eI","s":"2","p":"EMOzEVoFjbkS3ZS5JtmJO4LeZ4gydbr8iXNrEQAt1OR2","a":[{"i":"EC8Oej-3HAUpBY_kxzBK3B-0RV9j4dXw1H0NRKxJg7g-","s":"0","d":"EDBM1ys50vEJxRzvBjTOrmOhokELjVtozXy3ZbJ8-KFk"}]}-AABAAABtEQ7SoGt2IcZBMX0GaEaMqGdMsrGpj1fABDKgE5dA7s7AGXTkWrZjzA4GXkGXuOspi6upqBhpxr6d5ySeKQH"#;

        let kel = parse_event_stream(issuer_kel.as_bytes()).unwrap();
        let issuer_icp = kel[0].clone();
        let issuer_vcp_ixn = kel[1].clone();

        keri_processor.process(&issuer_icp)?;

        let tel_root = Builder::new().prefix("test-db").tempfile().unwrap();
        let tel_escrow_root = Builder::new().prefix("test-db").tempfile().unwrap();

        let db = Arc::new(EscrowDatabase::new(tel_escrow_root.path()).unwrap());
        let tel_events_db = Arc::new(RedbTelDatabase::new(&tel_root.path()).unwrap());

        let tel_storage = Arc::new(TelEventStorage::new(tel_events_db.clone()));
        let tel_bus = TelNotificationBus::new();

        let missing_issuer_escrow = Arc::new(MissingIssuerEscrow::new(
            tel_events_db,
            db,
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

        let processor = TelEventProcessor::new(keri_storage, tel_storage.clone(), Some(tel_bus));

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
        let verifiable_vcp = VerifiableEvent::new(vcp.clone(), dummy_source_seal.clone().into());
        processor.process(verifiable_vcp.clone())?;

        let st = tel_storage.compute_management_tel_state(&management_tel_prefix)?;
        assert_eq!(st, None);

        let man_event_from_db =
            tel_storage.get_management_event_at_sn(&management_tel_prefix, 0)?;
        assert!(man_event_from_db.is_none());

        keri_processor.process(&issuer_vcp_ixn)?;

        let management_state = tel_storage
            .compute_management_tel_state(&management_tel_prefix)?
            .unwrap();
        assert_eq!(management_state.sn, 0);

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
