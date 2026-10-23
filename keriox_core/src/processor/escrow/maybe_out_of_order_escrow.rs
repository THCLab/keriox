use std::{sync::Arc, time::Duration};

use crate::{
    database::{EscrowCreator, EscrowDatabase, EventDatabase},
    error::Error,
    prefix::IdentifierPrefix,
};

use crate::processor::{
    notification::{Notification, NotificationBus, Notifier},
    validator::EventValidator,
};

pub struct MaybeOutOfOrderEscrow<D: EventDatabase + EscrowCreator> {
    db: Arc<D>,
    pub(crate) escrowed_out_of_order: D::EscrowDatabaseType,
}

impl<D: EventDatabase + EscrowCreator + 'static> MaybeOutOfOrderEscrow<D> {
    pub fn new(db: Arc<D>, _duration: Duration) -> Self {
        let escrow_db = db.create_escrow_db("out_of_order_escrow");

        Self {
            db,
            escrowed_out_of_order: escrow_db,
        }
    }

    pub fn process_out_of_order_events(
        &self,
        bus: &NotificationBus,
        id: &IdentifierPrefix,
        sn: u64,
    ) -> Result<(), Error> {
        for event in self
            .escrowed_out_of_order
            .get_from_sn(id, sn)
            .map_err(|_| Error::DbError)?
        {
            let validator = EventValidator::new(self.db.clone());
            match validator.validate_event(&event) {
                Ok(_) => {
                    // add to kel
                    self.db
                        .add_kel_finalized_event(event.clone(), id)
                        .map_err(|_| Error::DbError)?;
                    // remove from escrow
                    self.escrowed_out_of_order.remove(&event.event_message);
                    bus.notify(&Notification::KeyEventAdded(event))?;
                    // stop processing the escrow if kel was updated. It needs to start again.
                    break;
                }
                Err(
                    Error::SignatureVerificationError
                    | Error::AbandonedIdentifier(_)
                    | Error::NonTransferableIdentifier(_)
                    | Error::ConfigTraitViolation(_)
                    | Error::EventAlreadyAccepted,
                ) => {
                    // remove from escrow
                    self.escrowed_out_of_order.remove(&event.event_message);
                }
                // The event is in order now but waits for something else:
                // hand it to the escrow that is told when that arrives.
                Err(Error::NotEnoughReceiptsError) => {
                    self.escrowed_out_of_order.remove(&event.event_message);
                    bus.notify(&Notification::PartiallyWitnessed(event))?;
                }
                Err(Error::NotEnoughSigsError) => {
                    self.escrowed_out_of_order.remove(&event.event_message);
                    bus.notify(&Notification::PartiallySigned(event))?;
                }
                Err(Error::MissingDelegatingEventError | Error::MissingDelegatorSealError(_)) => {
                    self.escrowed_out_of_order.remove(&event.event_message);
                    bus.notify(&Notification::MissingDelegatingEvent(event))?;
                }
                Err(_e) => (), // keep in escrow,
            }
        }

        Ok(())
    }
}

impl<D: EventDatabase + EscrowCreator + 'static> Notifier for MaybeOutOfOrderEscrow<D> {
    fn notify(&self, notification: &Notification, bus: &NotificationBus) -> Result<(), Error> {
        match notification {
            Notification::KeyEventAdded(ev_message) => {
                let id = ev_message.event_message.data.get_prefix();
                let sn = ev_message.event_message.data.sn;
                self.process_out_of_order_events(bus, &id, sn)?;
            }
            Notification::OutOfOrder(signed_event) => {
                // ignore events with no signatures
                if !signed_event.signatures.is_empty() {
                    self.escrowed_out_of_order
                        .insert(signed_event)
                        .map_err(|_| Error::DbError)?;
                }
            }
            _ => return Err(Error::SemanticError("Wrong notification".into())),
        }

        Ok(())
    }
}

#[test]
fn test_out_of_order() -> Result<(), Error> {
    use crate::database::redb::RedbDatabase;
    use crate::event_message::cesr_adapter::parse_cesr_stream_many;
    use crate::event_message::signed_event_message::{Message, Notice};
    use crate::processor::JustNotification;
    use crate::processor::{
        basic_processor::BasicProcessor, event_storage::EventStorage, Processor,
    };
    use tempfile::NamedTempFile;
    let kel = br#"{"v":"KERI10JSON000159_","t":"icp","d":"EGHq02i9na87rRvHP1IZgWAI5S1LDonTEt4K5bXbTCOI","i":"EGHq02i9na87rRvHP1IZgWAI5S1LDonTEt4K5bXbTCOI","s":"0","kt":"1","k":["DKOGw-nI6z8ArGcNalu-XvDQdNzH7w4MjrECqV3OQ71q"],"nt":"1","n":["EA8dyCfwMGpb5w5NfmALb3FlV7FIU36Nqsgja2t08IdX"],"bt":"0","b":["BGNVaRwXio_5EAenR4r7lV73NSxj57JXA5hM94sm4hpW"],"c":[],"a":[]}-KABAAA5RcdmNA_ZaBmjqh5vpdlgR_-ODc6h5gFR_SwykBY9Ltv5gi59Hww1tCYL2Y2esDhKeeX2-seoiGg5_XaVY9kP{"v":"KERI10JSON000160_","t":"rot","d":"EHLkSAdybW95N294JxZrydcABDiWaZ7iVb23DzX2qRB_","i":"EGHq02i9na87rRvHP1IZgWAI5S1LDonTEt4K5bXbTCOI","s":"1","p":"EGHq02i9na87rRvHP1IZgWAI5S1LDonTEt4K5bXbTCOI","kt":"1","k":["DFG_rn-pLFFVEs061EJ2DkFhLlnf7DkT9nC3IcBCVbBo"],"nt":"1","n":["EO4T-XooC3h_F-hyFg8U_ZKDGy9V9kowP039AshgzCbe"],"bt":"0","br":[],"ba":[],"a":[]}-KABAAD2EG3xkbzFAcTYOOBGBv5nx3WDLpaFtMplSKs_7XJPtD1ZuCRrd2mn1OX9Ly9ecrLVlmXjC3l9GxVOMwf9gCUI{"v":"KERI10JSON000160_","t":"rot","d":"ED96MWacB_nAxy7fRwj9VhKZ4moQbN37ocC7YQlUeYPU","i":"EGHq02i9na87rRvHP1IZgWAI5S1LDonTEt4K5bXbTCOI","s":"2","p":"EHLkSAdybW95N294JxZrydcABDiWaZ7iVb23DzX2qRB_","kt":"1","k":["DLKpQv9MmHGL7XbiVZh_bVmxpy07LNJRAAPmFwrGOp_7"],"nt":"1","n":["EP2PF5Mg1-gpCENuqhJLIKq7RPovyG-ZQ044DPgPaZoI"],"bt":"0","br":[],"ba":[],"a":[]}-KABAADR6M5cj905er-jQA3FippF_5Cl02cza4WTvreSK-8hRjJJS4qpxrNdVrH9tM1IOeN1RdcTBNJUie29leTk3acB{"v":"KERI10JSON000160_","t":"rot","d":"EP-96lQl3q59pazMaTxtDglRVPPq91-ANN2ac5B4FrFa","i":"EGHq02i9na87rRvHP1IZgWAI5S1LDonTEt4K5bXbTCOI","s":"3","p":"ED96MWacB_nAxy7fRwj9VhKZ4moQbN37ocC7YQlUeYPU","kt":"1","k":["DOVoe20RzPtjKruv6ET48Wk9FgqlghVu1m7qOKtefR4S"],"nt":"1","n":["EEoEs1ons8sP5-Z3eViRbJ2vd80yfROYFOLuJ2ChAxUb"],"bt":"0","br":[],"ba":[],"a":[]}-KABAAC668Ym3-BFClEz5w2Z9XgPBVxZhKyPnV1bFWpPb8WY1a8KALcV090ZVtDf-TfHOHa76XFfZ2CTG31fSG7X0BID{"v":"KERI10JSON000160_","t":"rot","d":"ECas3WfZcXrtmzJesSUeXcWO_1qMVUzekdYnsMYv7xoy","i":"EGHq02i9na87rRvHP1IZgWAI5S1LDonTEt4K5bXbTCOI","s":"4","p":"EP-96lQl3q59pazMaTxtDglRVPPq91-ANN2ac5B4FrFa","kt":"1","k":["DJPbny7g9-OelC-1lEEZC_ILnEPPzIoFGhUkmc85K3o3"],"nt":"1","n":["EKmlKzazAizGP5q4kobIc9bd1cLrMuXxmZCK4P6KwNYO"],"bt":"0","br":[],"ba":[],"a":[]}-KABAADArRDQlJW41E80VM-9McYPbIfaXlQtYAGyTNYHq3UajBzxKc_Fs-jwemFjLi5jOaemexq-EB8aeL4FRQVidxcL{"v":"KERI10JSON000160_","t":"rot","d":"ECxHQQXQ9WtZTDBIYIdT2Vb0kaV73UZkhv7yb5ia8EJo","i":"EGHq02i9na87rRvHP1IZgWAI5S1LDonTEt4K5bXbTCOI","s":"5","p":"ECas3WfZcXrtmzJesSUeXcWO_1qMVUzekdYnsMYv7xoy","kt":"1","k":["DPoBNHqZHgSuDxptgdsppepO61ll9XesnvtE57Hy-7Ao"],"nt":"1","n":["EEkVOqgjs9CsqoIKecevRYXWdfegd7ZE5gyhHQRrg_Ez"],"bt":"0","br":[],"ba":[],"a":[]}-KABAADlK0Qg1XuZtZca5xQAjjjuO-f5TLliCFZLD07RNQ4T8VYUnSqC_qyIAJRUj6wqXKdyzff7gGRRFLMBOS9wmTkF{"v":"KERI10JSON000160_","t":"rot","d":"EF2PpMozmiiomoVPtrjh-hl2yUOXV85-3WkY8RabDxec","i":"EGHq02i9na87rRvHP1IZgWAI5S1LDonTEt4K5bXbTCOI","s":"6","p":"ECxHQQXQ9WtZTDBIYIdT2Vb0kaV73UZkhv7yb5ia8EJo","kt":"1","k":["DNdt_G49Xnj0bFTpQhyXnc3A2dA5gbYahlqyArGAjc6Q"],"nt":"1","n":["EDKak9M18u89s7q-ZpEBXHayeOaNHRl_670VmQQuM9xI"],"bt":"0","br":[],"ba":[],"a":[]}-KABAABBCABwcUPheQiiFtRKUP08x2DETD7JV9OmfV8_fdFnqKjXLpHhkwDWbtkugWXHETWTmQcV2nHCKz31gER09RYN{"v":"KERI10JSON000160_","t":"rot","d":"EBz_VlAkL1vWGnKyGwqthMEs6JJLpB22sUeoKndr8Uii","i":"EGHq02i9na87rRvHP1IZgWAI5S1LDonTEt4K5bXbTCOI","s":"7","p":"EF2PpMozmiiomoVPtrjh-hl2yUOXV85-3WkY8RabDxec","kt":"1","k":["DD5up6y6WVaMXzastBgW-xarKyerE6vTiwkkyiaRrWWZ"],"nt":"1","n":["EKSp7OOwcM0A0vASGrsiZO9GXS10VauHlL8hfRZ4X2Q2"],"bt":"0","br":[],"ba":[],"a":[]}-KABAADaibD41clx1rbqyJeHZYPXKeJRUqJv1DshfNjpp3lQ70-6YIzTWGbP5w-nCX_k8wzj8GLb5Vl7qTS88NgPRS4E"#;
    let mut kell = parse_cesr_stream_many(kel)
        .unwrap()
        .into_iter()
        .map(|e| Message::try_from(e).unwrap());
    let ev1 = kell.next().unwrap();
    let ev2 = kell.next().unwrap();
    let ev3 = kell.next().unwrap();
    let ev4 = kell.next().unwrap();
    let ev5 = kell.next().unwrap();

    let (processor, storage, ooo_escrow) = {
        let events_db_path = NamedTempFile::new().unwrap();
        let redb = RedbDatabase::new(events_db_path.path()).unwrap();
        let events_db = Arc::new(redb);
        let processor = BasicProcessor::new(events_db.clone(), None);

        // Register out of order escrow, to save and reprocess out of order events
        let new_ooo = Arc::new(MaybeOutOfOrderEscrow::new(
            events_db.clone(),
            Duration::from_secs(60),
        ));
        processor.register_observer(
            new_ooo.clone(),
            &[
                JustNotification::OutOfOrder,
                JustNotification::KeyEventAdded,
            ],
        )?;
        (processor, EventStorage::new(events_db.clone()), new_ooo)
    };
    let id: IdentifierPrefix = "EGHq02i9na87rRvHP1IZgWAI5S1LDonTEt4K5bXbTCOI".parse()?;

    processor.process(&ev1)?;
    assert_eq!(storage.get_state(&id).unwrap().sn, 0);

    processor.process(&ev4.clone())?;
    let mut escrowed = ooo_escrow.escrowed_out_of_order.get(&id, 3).unwrap();
    assert_eq!(
        escrowed.next().map(|e| Message::Notice(Notice::Event(e))),
        Some(ev4.clone())
    );
    assert!(escrowed.next().is_none());

    processor.process(&ev3.clone())?;
    let mut escrowed = ooo_escrow
        .escrowed_out_of_order
        .get_from_sn(&id, 2)
        .unwrap();
    assert_eq!(
        escrowed.next().map(|e| Message::Notice(Notice::Event(e))),
        Some(ev3.clone())
    );
    assert_eq!(
        escrowed.next().map(|e| Message::Notice(Notice::Event(e))),
        Some(ev4.clone())
    );
    assert!(escrowed.next().is_none());

    processor.process(&ev5.clone())?;
    let mut escrowed = ooo_escrow
        .escrowed_out_of_order
        .get_from_sn(&id, 2)
        .unwrap();
    assert_eq!(
        escrowed.next().map(|e| Message::Notice(Notice::Event(e))),
        Some(ev3.clone())
    );
    assert_eq!(
        escrowed.next().map(|e| Message::Notice(Notice::Event(e))),
        Some(ev4.clone())
    );
    assert_eq!(
        escrowed.next().map(|e| Message::Notice(Notice::Event(e))),
        Some(ev5.clone())
    );
    assert!(escrowed.next().is_none());

    assert_eq!(storage.get_state(&id).unwrap().sn, 0);
    // check out of order table
    assert_eq!(
        ooo_escrow
            .escrowed_out_of_order
            .get_from_sn(&id, 2)
            .unwrap()
            .count(),
        3
    );

    processor.process(&ev2)?;

    assert_eq!(storage.get_state(&id).unwrap().sn, 4);
    // Check if out of order is empty
    let mut escrowed = ooo_escrow
        .escrowed_out_of_order
        .get_from_sn(&id, 0)
        .unwrap();
    assert!(escrowed.next().is_none());

    Ok(())
}
