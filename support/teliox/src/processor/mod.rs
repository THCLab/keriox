use std::sync::Arc;

use keri_core::{database::EventDatabase, processor::event_storage::EventStorage};

use crate::{
    database::TelEventDatabase,
    error::Error,
    event::{verifiable_event::VerifiableEvent, Event},
    query::SignedTelQuery,
};

use self::{
    notification::{TelNotification, TelNotificationBus, TelNotificationKind, TelNotifier},
    storage::TelEventStorage,
    validator::TelEventValidator,
};

#[cfg(feature = "storage-redb")]
pub mod escrow;
pub mod notification;
pub mod storage;
pub mod validator;

pub struct TelEventProcessor<D: TelEventDatabase, K: EventDatabase> {
    kel_reference: Arc<EventStorage<K>>,
    pub tel_reference: Arc<TelEventStorage<D>>,
    pub publisher: TelNotificationBus,
}

impl<D: TelEventDatabase, K: EventDatabase> TelEventProcessor<D, K> {
    pub fn new(
        kel_reference: Arc<EventStorage<K>>,
        tel_reference: Arc<TelEventStorage<D>>,
        tel_publisher: Option<TelNotificationBus>,
    ) -> Self {
        Self {
            kel_reference,
            tel_reference,
            publisher: tel_publisher.unwrap_or_default(),
        }
    }

    pub fn register_observer(
        &mut self,
        observer: Arc<dyn TelNotifier + Send + Sync>,
        notifications: Vec<TelNotificationKind>,
    ) -> Result<(), Error> {
        self.publisher.register_observer(observer, notifications)?;
        Ok(())
    }

    // Checks verifiable event and adds it to database.
    pub fn process(&self, event: VerifiableEvent) -> Result<(), Error> {
        let validator =
            TelEventValidator::new(self.tel_reference.clone(), self.kel_reference.clone());
        match &event.event.clone() {
            Event::Management(ref man) => match validator.validate_management(man, &event.seal) {
                Ok(_) => {
                    self.tel_reference
                        .db
                        .add_new_event(event.clone(), &man.data.prefix)
                        .unwrap();
                    self.publisher
                        .notify(&TelNotification::TelEventAdded(event))?;
                    Ok(())
                }
                Err(e) => match e {
                    Error::OutOfOrderError => {
                        self.publisher.notify(&TelNotification::OutOfOrder(event))
                    }
                    Error::MissingIssuerEventError => self
                        .publisher
                        .notify(&TelNotification::MissingIssuer(event)),
                    Error::MissingRegistryError => self
                        .publisher
                        .notify(&TelNotification::MissingRegistry(event)),
                    Error::EventAlreadySavedError => {
                        // Means that vc of given registry is already accepted
                        Ok(())
                    }
                    e => Err(e),
                },
            },
            Event::Vc(ref vc_ev) => {
                match validator.validate_vc(vc_ev, &event.seal) {
                    Ok(_) => {
                        self.tel_reference
                            .db
                            .add_new_event(event.clone(), &vc_ev.data.data.prefix)
                            .unwrap();
                        self.publisher
                            .notify(&TelNotification::TelEventAdded(event))
                    }
                    Err(Error::MissingIssuerEventError) => self
                        .publisher
                        .notify(&TelNotification::MissingIssuer(event)),
                    Err(Error::MissingRegistryError) => self
                        .publisher
                        .notify(&TelNotification::MissingRegistry(event)),
                    Err(Error::OutOfOrderError) => {
                        self.publisher.notify(&TelNotification::OutOfOrder(event))
                    }
                    Err(Error::EventAlreadySavedError) => {
                        // Means that vc of given id is already accepted
                        Ok(())
                    }
                    Err(e) => Err(e),
                }
            }
        }
    }

    pub fn process_signed_query(&self, qr: SignedTelQuery) -> Result<TelReplyType, Error> {
        let signature = qr.signature;
        // check signatures
        let ver_result = signature.verify(&(qr.query.encode()?), &self.kel_reference)?;

        if !ver_result {
            return Err(Error::Generic("Wrong query event signature".to_string()));
        };

        // unpack and check what's inside
        self.tel_reference.process_query(&qr.query.data.data)
    }
}

pub enum TelReplyType {
    Tel(Vec<u8>),
}

impl ToString for TelReplyType {
    fn to_string(&self) -> String {
        match self {
            TelReplyType::Tel(tel) => String::from_utf8(tel.to_vec()).unwrap(),
        }
    }
}
