use std::{sync::Arc, time::Duration};

use crate::{
    database::{EscrowCreator, EscrowDatabase, EventDatabase},
    error::Error,
    event::KeyEvent,
    event_message::{msg::KeriEvent, signed_event_message::SignedEventMessage},
    processor::{
        notification::{Notification, NotificationBus, Notifier},
        validator::EventValidator,
    },
};

pub struct PartiallySignedEscrow<D: EventDatabase + EscrowCreator> {
    db: Arc<D>,
    pub escrowed_partially_signed: D::EscrowDatabaseType,
}

impl<D: EventDatabase + EscrowCreator + 'static> PartiallySignedEscrow<D> {
    pub fn new(db: Arc<D>, _duration: Duration) -> Self {
        let escrow_db = db.create_escrow_db("partially_signed_escrow");
        Self {
            db,
            escrowed_partially_signed: escrow_db,
        }
    }

    pub fn get_partially_signed_for_event(
        &self,
        event: KeriEvent<KeyEvent>,
    ) -> Option<SignedEventMessage>
    where
        <D::EscrowDatabaseType as crate::database::EscrowDatabase>::Error: std::fmt::Debug,
    {
        let id = event.data.get_prefix();
        let sn = event.data.sn;
        self.escrowed_partially_signed
            .get(&id, sn)
            .unwrap()
            .find(|escrowed_event| escrowed_event.event_message == event)
    }

    fn remove_partially_signed(&self, event: &KeriEvent<KeyEvent>) -> Result<(), Error> {
        self.escrowed_partially_signed.remove(event);

        Ok(())
    }

    pub fn process_partially_signed_events(
        &self,
        bus: &NotificationBus,
        signed_event: &SignedEventMessage,
    ) -> Result<(), Error> {
        let id = signed_event.event_message.data.get_prefix();
        let sn = signed_event.event_message.data.sn;
        if let Some(esc) = self
            .escrowed_partially_signed
            .get(&id, sn)
            .map_err(|_| Error::DbError)?
            .find(|event| event.event_message == signed_event.event_message)
        {
            let mut signatures = esc.signatures;
            let signatures_from_event = signed_event.signatures.clone();
            let without_duplicates = signatures_from_event
                .into_iter()
                .filter(|sig| !signatures.contains(sig))
                .collect::<Vec<_>>();

            signatures.append(&mut without_duplicates.clone());

            let new_event = SignedEventMessage {
                signatures,
                ..signed_event.to_owned()
            };

            let validator = EventValidator::new(self.db.clone());
            match validator.validate_event(&new_event) {
                Ok(_) => {
                    // add to kel
                    self.db
                        .add_kel_finalized_event(new_event.clone(), &id)
                        .unwrap_or_default();
                    // remove from escrow
                    self.remove_partially_signed(&new_event.event_message)?;
                    bus.notify(&Notification::KeyEventAdded(new_event))?;
                }
                Err(Error::NotEnoughReceiptsError) => {
                    // remove from escrow
                    self.remove_partially_signed(&new_event.event_message)?;
                    bus.notify(&Notification::PartiallyWitnessed(new_event))?;
                }
                Err(Error::MissingDelegatingEventError)
                | Err(Error::MissingDelegatorSealError(_)) => {
                    // remove from escrow
                    self.remove_partially_signed(&new_event.event_message)?;
                    bus.notify(&Notification::MissingDelegatingEvent(new_event))?;
                }
                Err(Error::SignatureVerificationError) => {
                    // ignore
                }
                Err(Error::NotEnoughSigsError) => {
                    // keep in escrow and save new partially signed event
                    let to_add = SignedEventMessage {
                        signatures: without_duplicates,
                        ..signed_event.to_owned()
                    };
                    self.escrowed_partially_signed
                        .insert(&to_add)
                        .map_err(|_| Error::DbError)?;
                }
                Err(_e) => {
                    // keep in escrow
                }
            }
        } else {
            self.escrowed_partially_signed
                .insert(signed_event)
                .map_err(|_| Error::DbError)?;
        };

        Ok(())
    }
}

impl<D: EventDatabase + EscrowCreator + 'static> Notifier for PartiallySignedEscrow<D> {
    fn notify(&self, notification: &Notification, bus: &NotificationBus) -> Result<(), Error> {
        match notification {
            Notification::PartiallySigned(ev) => {
                if ev.signatures.is_empty() {
                    // ignore events with no signatures
                    Ok(())
                } else {
                    self.process_partially_signed_events(bus, ev)
                }
            }
            _ => Err(Error::SemanticError("Wrong notification".into())),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{sync::Arc, time::Duration};

    use cesrox::{parse, parse_many, payload::parse_payload};
    use tempfile::NamedTempFile;

    use crate::{
        actor::prelude::{BasicProcessor, EventStorage, Message},
        database::{redb::RedbDatabase, EscrowDatabase},
        error::Error,
        event_message::{
            cesr_adapter::EventType,
            signed_event_message::{Notice, SignedEventMessage},
        },
        prefix::IdentifierPrefix,
        processor::{
            escrow::{
                maybe_out_of_order_escrow::MaybeOutOfOrderEscrow,
                partially_signed_escrow::PartiallySignedEscrow,
            },
            notification::JustNotification,
            Processor,
        },
    };

    #[test]
    fn test_escrow_missing_signatures() -> Result<(), Error> {
        let kel = br#"{"v":"KERI10JSON000159_","t":"icp","d":"EMTMYJQ3Eaq8YjG94c_GGvihe5cW8vFFXX2PezAwrn2A","i":"EMTMYJQ3Eaq8YjG94c_GGvihe5cW8vFFXX2PezAwrn2A","s":"0","kt":"1","k":["DJPJ89wKDXMW9Mrg18nZdqp37gCEXuCrTojzVXhHwGT6"],"nt":"1","n":["ENey4-IfkllvEDtKtlFXlr0bhAFFfHQp-n6n2MYEick0"],"bt":"0","b":["DHEOrU8GRgLhjFxz-72koNrxJ5Gyj57B_ZGmYjqbOf4W"],"c":[],"a":[]}-AABAACuardPTXF2hZVuFkhbD6-r84g6p3RoZl_nJRVH6kEOmqxZpw1fj37b7s8LJ649TecIu4Pxb-A2Lu05AptmlBkO{"v":"KERI10JSON000160_","t":"rot","d":"EIBUvQrJbIHvkzQt1hZs1-chTR7FELwknEhQKTS-ku_e","i":"EMTMYJQ3Eaq8YjG94c_GGvihe5cW8vFFXX2PezAwrn2A","s":"1","p":"EMTMYJQ3Eaq8YjG94c_GGvihe5cW8vFFXX2PezAwrn2A","kt":"1","k":["DGuK-ColPgPuH_FCZopzjQAoMN2aNzk3rioNewx1_2El"],"nt":"1","n":["EB78ym8c7Z86gmZWZawXYCk5uMy8H6fC5iPdd3d7VPvk"],"bt":"0","br":[],"ba":[],"a":[]}-AABAAAyw89UHMWvXFyDxJva0uCslgPadFzdNnhFzVjaCvvmV0l6vtXKln1wiy382QbOb69u9DuPgIQUdXLIW9xMJAMI"#;
        let event_without_signature_str = br#"{"v":"KERI10JSON0000cb_","t":"ixn","d":"ENSAcKy3MKyQoYJtXVaNiWHHcFSKwnnN0X_x9-i70q0N","i":"EMTMYJQ3Eaq8YjG94c_GGvihe5cW8vFFXX2PezAwrn2A","s":"2","p":"EIBUvQrJbIHvkzQt1hZs1-chTR7FELwknEhQKTS-ku_e","a":[]}-AABAAC-Oy9w2O16tEzQfIW1TjExYyRbQyBeuc6Etrkdc-QIN_wS3iyw_LYqLI6Zmp34UBkdNv0ZLEjTTcX8dyuJVq0M"#;
        let mut kell = parse_many(kel)
            .unwrap()
            .1
            .into_iter()
            .map(|e| Message::try_from(e).unwrap());
        let ev1 = kell.next().unwrap();
        let ev2 = kell.next().unwrap();
        let (event_without_signatures, _event) = match parse_payload(event_without_signature_str)
            .unwrap()
            .1
            .try_into()?
        {
            EventType::KeyEvent(event) => (
                Message::Notice(Notice::Event(SignedEventMessage {
                    event_message: event.clone(),
                    signatures: vec![],
                    witness_receipts: None,
                    delegator_seal: None,
                })),
                event,
            ),
            _ => unreachable!(),
        };

        use tempfile::Builder;

        let (processor, storage, ooo_escrow, ps_escrow) = {
            let witness_root = Builder::new().prefix("test-db").tempdir().unwrap();
            let path = witness_root.path();
            let events_db_path = NamedTempFile::new().unwrap();
            let events_db = Arc::new(RedbDatabase::new(events_db_path.path()).unwrap());
            let processor = BasicProcessor::new(events_db.clone(), None);

            // Register out of order escrow, to save and reprocess out of order events
            let ooo_escrow = Arc::new(MaybeOutOfOrderEscrow::new(
                events_db.clone(),
                Duration::from_secs(10),
            ));
            processor.register_observer(
                ooo_escrow.clone(),
                &[
                    JustNotification::OutOfOrder,
                    JustNotification::KeyEventAdded,
                ],
            )?;

            let ps_escrow = Arc::new(PartiallySignedEscrow::new(
                events_db.clone(),
                Duration::from_secs(10),
            ));
            processor.register_observer(
                ps_escrow.clone(),
                &[
                    JustNotification::PartiallySigned,
                    JustNotification::KeyEventAdded,
                ],
            )?;

            std::fs::create_dir_all(path).unwrap();
            (
                BasicProcessor::new(events_db.clone(), None),
                EventStorage::new(events_db.clone()),
                ooo_escrow,
                ps_escrow,
            )
        };
        let id: IdentifierPrefix = "EMTMYJQ3Eaq8YjG94c_GGvihe5cW8vFFXX2PezAwrn2A".parse()?;

        processor.process(&ev1)?;
        assert_eq!(storage.get_state(&id).unwrap().sn, 0);

        // Process out of order event without signatures
        processor.process(&event_without_signatures)?;

        assert!(ooo_escrow
            .escrowed_out_of_order
            .get_from_sn(&id, 0)
            .unwrap()
            .next()
            .is_none(),);

        // try to process unsigned event, but in order
        processor.process(&ev2)?;
        processor.process(&event_without_signatures)?;

        // check partially signed escrow
        let mut escrowed = ps_escrow.escrowed_partially_signed.get_from_sn(&id, 0)?;
        assert!(escrowed.next().is_none());

        Ok(())
    }

    #[test]
    fn test_partially_sign_escrow() -> Result<(), Error> {
        use tempfile::Builder;

        // events from keripy/tests/core/test_escrow.py::test_partial_signed_escrow
        let (processor, storage, ps_escrow) = {
            let witness_root = Builder::new().prefix("test-db").tempdir().unwrap();
            let path = witness_root.path();
            std::fs::create_dir_all(path).unwrap();
            let events_db_path = NamedTempFile::new().unwrap();
            let events_db = Arc::new(RedbDatabase::new(events_db_path.path()).unwrap());
            let processor = BasicProcessor::new(events_db.clone(), None);

            // Register partially signed escrow, to save and reprocess partially signed events
            let ps_escrow = Arc::new(PartiallySignedEscrow::new(
                events_db.clone(),
                Duration::from_secs(10),
            ));
            processor.register_observer(ps_escrow.clone(), &[JustNotification::PartiallySigned])?;

            (processor, EventStorage::new(events_db.clone()), ps_escrow)
        };

        let parse_messagee = |raw_event| {
            let parsed = parse(raw_event).unwrap().1;
            Message::try_from(parsed).unwrap()
        };

        let id: IdentifierPrefix = "EIL2dvwm6lYAsyKKtzxIEFm51gSfwe3IIZSx8kI8ve7_".parse()?;
        let icp_raw = br#"{"v":"KERI10JSON000207_","t":"icp","d":"EIL2dvwm6lYAsyKKtzxIEFm51gSfwe3IIZSx8kI8ve7_","i":"EIL2dvwm6lYAsyKKtzxIEFm51gSfwe3IIZSx8kI8ve7_","s":"0","kt":["1/2","1/2","1/2"],"k":["DCuDiSPCTq-qBBFDHkhf1_kmysrH8KSsFvoaOSgEbx-X","DNUWS4GJHtBpn2Zvgh_ALFuB6E1OJvtphYLvJG8KfI0F","DAVcM7pvoz37lF1HBxFnaZQeGHKC9wVhlytEzKBfzXhV"],"nt":["1/2","1/2","1/2"],"n":["EFQZkN8MMEtZzaS-Tq1EEbH886vsf5SzwicSn_ywbzTy","ENOQnUj8GNr1ICJ1P4qmC3-aHTrpZqKVpZhvHCBVWE1p","EDFH1MfEJWlI9PpMbgBi_RGP7L4UivrLfozFucuEaWVH"],"bt":"0","b":[],"c":[],"a":[]}-AABAAC3xWTpnv14_khneBqDlrK7JHPUoHNJhWMIXzXbK80RVyEYV7iMsWaAXfepkRsyELBLd25atAtE3iLeDn1I-gUM'"#;
        let icp_first_sig = parse_messagee(icp_raw);

        let icp_raw = br#"{"v":"KERI10JSON000207_","t":"icp","d":"EIL2dvwm6lYAsyKKtzxIEFm51gSfwe3IIZSx8kI8ve7_","i":"EIL2dvwm6lYAsyKKtzxIEFm51gSfwe3IIZSx8kI8ve7_","s":"0","kt":["1/2","1/2","1/2"],"k":["DCuDiSPCTq-qBBFDHkhf1_kmysrH8KSsFvoaOSgEbx-X","DNUWS4GJHtBpn2Zvgh_ALFuB6E1OJvtphYLvJG8KfI0F","DAVcM7pvoz37lF1HBxFnaZQeGHKC9wVhlytEzKBfzXhV"],"nt":["1/2","1/2","1/2"],"n":["EFQZkN8MMEtZzaS-Tq1EEbH886vsf5SzwicSn_ywbzTy","ENOQnUj8GNr1ICJ1P4qmC3-aHTrpZqKVpZhvHCBVWE1p","EDFH1MfEJWlI9PpMbgBi_RGP7L4UivrLfozFucuEaWVH"],"bt":"0","b":[],"c":[],"a":[]}-AABACAwNb8Lj-vxJYMi_vIH-ETGG0dVfqIk4ihrQvV1iL1_07eWfu4BwRYCPCZDo0F0Xbkz0DP4xXVfChR-lFd2npUG"#;
        let icp_second_sig = parse_messagee(icp_raw);

        processor.process(&icp_first_sig)?;
        let icp_event = if let Message::Notice(Notice::Event(ev)) = icp_first_sig.clone() {
            Some(ev.event_message)
        } else {
            None
        }
        .unwrap();

        let escrowed = ps_escrow
            .get_partially_signed_for_event(icp_event.clone())
            .unwrap();
        assert_eq!(
            Message::Notice(Notice::Event(escrowed)),
            icp_first_sig.clone()
        );

        // check if event was accepted into kel
        assert_eq!(storage.get_state(&id), None);

        // Proces the same event with another signature
        processor.process(&icp_second_sig)?;

        // Now event is fully signed, check if escrow is empty
        assert!(ps_escrow
            .get_partially_signed_for_event(icp_event.clone())
            .is_none());
        // check if event was accepted
        assert!(storage.get_state(&id).is_some());

        let ixn = br#"{"v":"KERI10JSON0000cb_","t":"ixn","d":"EODgCVSGS9S8ZaOr89HKDP_Zll21C8zbUBjbBU1HjGEk","i":"EIL2dvwm6lYAsyKKtzxIEFm51gSfwe3IIZSx8kI8ve7_","s":"1","p":"EIL2dvwm6lYAsyKKtzxIEFm51gSfwe3IIZSx8kI8ve7_","a":[]}-AABABC3seofRQNJPKgqXy6Y2N_VsewM1QkG7Y1hfIOosAKW8EdB9nUvqofUhOdSuH2LUzV3S4uenFe-G8EP_VhQaLAH"#;
        let ixn_first_sig = parse_messagee(ixn);

        let ixn2 = br#"{"v":"KERI10JSON0000cb_","t":"ixn","d":"EODgCVSGS9S8ZaOr89HKDP_Zll21C8zbUBjbBU1HjGEk","i":"EIL2dvwm6lYAsyKKtzxIEFm51gSfwe3IIZSx8kI8ve7_","s":"1","p":"EIL2dvwm6lYAsyKKtzxIEFm51gSfwe3IIZSx8kI8ve7_","a":[]}-AABAAAsZ-qmrZIreJgAd34xZEb_mHTc7tjgwMzMbd31sRyt8a1osduDv_uzeqWiicSauNyiehjfPjeJa1ZJfOGBgbEP"#;
        let ixn_second_sig = parse_messagee(ixn2);

        let ixn_event = if let Message::Notice(Notice::Event(ev)) = ixn_first_sig.clone() {
            Some(ev.event_message)
        } else {
            None
        }
        .unwrap();

        processor.process(&ixn_first_sig)?;

        // check if event was accepted into kel
        assert_eq!(storage.get_state(&id).unwrap().sn, 0);

        // check escrow
        assert_eq!(
            ps_escrow
                .escrowed_partially_signed
                .get_from_sn(&id, 0)
                .unwrap()
                .count(),
            1
        );

        // Proces the same event with another signature
        processor.process(&ixn_second_sig)?;

        // Now event is fully signed, check if escrow is empty
        assert!(ps_escrow
            .get_partially_signed_for_event(ixn_event)
            .is_none());
        // check if event was accepted
        assert_eq!(storage.get_state(&id).unwrap().sn, 1);

        let rot = parse_messagee(br#"{"v":"KERI10JSON0002a6_","t":"rot","d":"EBV201a_Q2aMRPB2JlpTybBBO4Osp7o1-jRvSwayYFmy","i":"EIL2dvwm6lYAsyKKtzxIEFm51gSfwe3IIZSx8kI8ve7_","s":"2","p":"EODgCVSGS9S8ZaOr89HKDP_Zll21C8zbUBjbBU1HjGEk","kt":["1/2","1/2","1/2"],"k":["DHqJ2DNmypwMKelWXLgl3V-9pDRcOenM5Wf03O1xx1Ri","DEIISiMvtnaPTpMHkoGs4d0JdbwjreW53OUBfMedLUaF","DDQFJ_uXcZum_DY6NNTtI5UrTEQo6PRWEANpn6hVtfyQ"],"nt":[["1/2","1/2","1/2"],["1","1"]],"n":["EJsp5uWsQOsioYA16kbCZW9HPMr0rEaU4NUvfm6QTYd2","EFxT53mK2-1sAnh8VcLEL1HowQp0t84dfIWRaju5Ef61","EETqITKVCCpOS6aDPiZFJOSWll2i39xaFQkfAYsG18I_","EGGvSfHct9RLnwIMMkNrG7I0bRYO1uoUnP4QbnDFzBI6","ELTnTK-3KiF4zvY9WC0ZJjmFm8NFacQtuNiA8KuQkHQe"],"bt":"0","br":[],"ba":[],"a":[]}-AADAACj5KQr7VHyjvkBETGvqTk_lt2w0-oEVIpO_8acwJNygvJe1-ZsgcK02yBwHJFJ7N-qemGaDRsIxFnuJ3ya3TwAABDu4EVUGhvMWjdMhMgdJ-D_XapyM4lnGbaLKhjc7ndi39LCq-Ap9C4flibBVbqYpbwSyheHRYiyUythE5sks2kEACAkF7H6pJS_-aLAkCDVEFI4hK6aqMojyf--JFHtqVgG1mloIpeDQATu6DODSxv8zTZHwOaJwSERMk3fd6eVXIgG"#);

        processor.process(&rot)?;
        // assert_eq!(storage.get_state(&id).unwrap().unwrap().sn, 2);
        Ok(())
    }
}
