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
                Err(Error::SignatureVerificationError) => {
                    // remove from escrow
                    self.escrowed_out_of_order.remove(&event.event_message);
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
    use crate::event_message::signed_event_message::{Message, Notice};
    use crate::processor::JustNotification;
    use crate::processor::{
        basic_processor::BasicProcessor, event_storage::EventStorage, Processor,
    };
    use cesrox::parse_many;
    use tempfile::NamedTempFile;
    let kel = br#"{"v":"KERI10JSON000159_","t":"icp","d":"EO8cED9H5XPqBdoVatgBkEuSP8yXic7HtWpkex-9e0sL","i":"EO8cED9H5XPqBdoVatgBkEuSP8yXic7HtWpkex-9e0sL","s":"0","kt":"1","k":["DODv7KGqEEhAP7-VYXzZvNi5wmgEB8w5y6HLUQL08PNh"],"nt":"1","n":["ECo41Mn5wku-tQd7L4Hp65KhaX1KkdTtSY_NXx4rQphS"],"bt":"0","b":["DPOIlcZk_GLVCVtG7KLbDQa2a5drXGt09wpaeY93G--1"],"c":[],"a":[]}-AABAADtEDd5x0DRfSlGl99G2V3aiJQlILTMG8LHNbG6V3ticL8r1vMK8-nmhZBhZglI06mVChxc-EkgqWPzPlI2rAwD{"v":"KERI10JSON000160_","t":"rot","d":"EDBBxc3_cczsEld6szaFdmhR3JyOhnYaDCCdo_wDe95p","i":"EO8cED9H5XPqBdoVatgBkEuSP8yXic7HtWpkex-9e0sL","s":"1","p":"EO8cED9H5XPqBdoVatgBkEuSP8yXic7HtWpkex-9e0sL","kt":"1","k":["DIgRd-GK29iB-G7tao3-BCdMbUCATveeMrzivmmmM_Nf"],"nt":"1","n":["EBrEok_A-yJGpR9GH_ktdd11x3UR0cHaCg0nzAnYLgGj"],"bt":"0","br":[],"ba":[],"a":[]}-AABAADLgLBVFeCOP8t-sxOWKif-JbQ-PnOz0W7aZCuLPOUEri-OdGXjOV2d3y6-R_SsS2U3toE3TNVJ9UyO5NhBSkkO{"v":"KERI10JSON000160_","t":"rot","d":"ENtkE-NChURiXS5j8ES9GeX9VCqr5PLxilygqUJQ5Wr9","i":"EO8cED9H5XPqBdoVatgBkEuSP8yXic7HtWpkex-9e0sL","s":"2","p":"EDBBxc3_cczsEld6szaFdmhR3JyOhnYaDCCdo_wDe95p","kt":"1","k":["DGx72gYpAdz0N3br4blkVRRoIASdcBTJaqtLnGI6PXHV"],"nt":"1","n":["EMEVqKOHmF9juqQSmphqjnP24tT__JILJJ2Z4u9QKSUn"],"bt":"0","br":[],"ba":[],"a":[]}-AABAAAHF__vhEKj4kn1uW0fdBRS75nyG3uvJuEfcOdnx4sfy2vNirkDLkm6WGluUVDfQ7y9_b2TIaIHLfAoBefjNBkF{"v":"KERI10JSON000160_","t":"rot","d":"EP0HwW561f8fXuZdau8FyVoQxYTqADGfp12EnI6-Wl6T","i":"EO8cED9H5XPqBdoVatgBkEuSP8yXic7HtWpkex-9e0sL","s":"3","p":"ENtkE-NChURiXS5j8ES9GeX9VCqr5PLxilygqUJQ5Wr9","kt":"1","k":["DFXuPGU9uFziSr3uQuDo7yKJFmcyURvTq8YOfLfNHf6r"],"nt":"1","n":["EO3OeLeP4Ux570nxE0cuK76Bn0I2NAyA1artuMiyASJf"],"bt":"0","br":[],"ba":[],"a":[]}-AABAAAXiKK5er1d8dlAorz6SVhp6xs33eoEKSn2JZrrUHTFZz4xjIa_Ectg9Jyvs12JkdjkNf3VUQ2GMsnfgBpIkXMB{"v":"KERI10JSON000160_","t":"rot","d":"EGzDR2bgvFESAlpZ_BiiVrefq6S_Ea7navqFyB8EOu6Q","i":"EO8cED9H5XPqBdoVatgBkEuSP8yXic7HtWpkex-9e0sL","s":"4","p":"EP0HwW561f8fXuZdau8FyVoQxYTqADGfp12EnI6-Wl6T","kt":"1","k":["DHkJs10SLaBPMBsPx8X6x4TozQMM8OuAzgj681jYSckq"],"nt":"1","n":["ELRF262pZpt8-UiEX5TSsCFiZ1NmRHkvHIq-M6mFKDw_"],"bt":"0","br":[],"ba":[],"a":[]}-AABAACx23xFm12mxnmA413AJCGK67SF5OHb6hlz6qbZjyWbkAqtmqmo2_SRFHtbSFpZ5yIVObSf_F9yr8sRQ-_pJg0F{"v":"KERI10JSON000160_","t":"rot","d":"EKlpPRdR6NmMHhJ3XuDt7cuPVkfUy11leY6US9bP3jVx","i":"EO8cED9H5XPqBdoVatgBkEuSP8yXic7HtWpkex-9e0sL","s":"5","p":"EGzDR2bgvFESAlpZ_BiiVrefq6S_Ea7navqFyB8EOu6Q","kt":"1","k":["DOFD9XUnKnAUyn0QjYq0BouHyYjvmHN7T2nnVaxr7VHz"],"nt":"1","n":["EFz-ndoE5OXjvD0-UdQAzepB8zpnfk44HN2h8aWmdnKB"],"bt":"0","br":[],"ba":[],"a":[]}-AABAABKlwj4nLkk8q-1YhxA-NjTJCw6AiqyopKvp-MJgx-FKzgZecMmtGm3q5SLImR8P0evrVGL8-DvI-kF9FzYN5YP{"v":"KERI10JSON000160_","t":"rot","d":"ELQRtBD0vqZOQRTc_uQ0_WebeSM-xLcIog7QPyCDtANg","i":"EO8cED9H5XPqBdoVatgBkEuSP8yXic7HtWpkex-9e0sL","s":"6","p":"EKlpPRdR6NmMHhJ3XuDt7cuPVkfUy11leY6US9bP3jVx","kt":"1","k":["DMrq2ktTKWxE5jjhDKDOz1T8a4R0ZGsikc7M-p5k-Rzp"],"nt":"1","n":["EKw6XLOELmjxU-N_EDuUQ7v1XfodiBVyf2nU2zaSIe05"],"bt":"0","br":[],"ba":[],"a":[]}-AABAABzuuhSMYnxQVJ-K2lJP2WOfUP-oiQAp1Dm2685U-s-91bQovUHAoMoVFWcq0FnxC8W7rQHLXw-Wgt_-lo34u4H{"v":"KERI10JSON000160_","t":"rot","d":"EBOeYHB245lnMJY4or8FvfCaoYlwMVwE5Hr49VE6uXK8","i":"EO8cED9H5XPqBdoVatgBkEuSP8yXic7HtWpkex-9e0sL","s":"7","p":"ELQRtBD0vqZOQRTc_uQ0_WebeSM-xLcIog7QPyCDtANg","kt":"1","k":["DApxTJjlbWOgHIMXR_qrryjCIlLFPqnaSRo2M1FFmp4I"],"nt":"1","n":["EOdAKz4CYF6RFZzs_Chyih7QRgcfcZaJ_G02Y-4lrfHg"],"bt":"0","br":[],"ba":[],"a":[]}-AABAAAmR-tO3N1b7b2ZCZmlaSYmQbgHE0T9wZANzXdezQ2b9XPS0RWJcMfHCtpn3qj0Jxhhij1OfMGPSqtshVtEXsYC"#;
    let mut kell = parse_many(kel)
        .unwrap()
        .1
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
    let id: IdentifierPrefix = "EO8cED9H5XPqBdoVatgBkEuSP8yXic7HtWpkex-9e0sL".parse()?;

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
