use std::sync::Arc;

use keri::processor::event_storage::EventStorage;

use crate::{
    error::Error,
    event::{verifiable_event::VerifiableEvent, Event},
};

use self::{
    notification::{TelNotification, TelNotificationBus, TelNotificationKind, TelNotifier},
    storage::TelEventStorage,
    validator::TelEventValidator,
};

pub mod escrow;
pub mod notification;
pub mod storage;
pub mod validator;

pub struct TelEventProcessor {
    kel_reference: Arc<EventStorage>,
    pub tel_reference: Arc<TelEventStorage>,
    pub publisher: TelNotificationBus,
}

impl TelEventProcessor {
    pub fn new(
        kel_reference: Arc<EventStorage>,
        tel_reference: Arc<TelEventStorage>,
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

    // Process verifiable event. It doesn't check if source seal is correct. Just add event to tel.
    pub fn process(&self, event: VerifiableEvent) -> Result<(), Error> {
        let validator =
            TelEventValidator::new(self.tel_reference.db.clone(), self.kel_reference.clone());
        match &event.event.clone() {
            Event::Management(ref man) => match validator.validate_management(&man, &event.seal) {
                Ok(_) => {
                    self.tel_reference
                        .db
                        .add_new_management_event(event.clone(), &man.data.prefix)
                        .unwrap();
                    self.publisher
                        .notify(&TelNotification::TelEventAdded(event.event))?;
                    Ok(())
                }
                Err(e) => match e {
                    Error::MissingSealError => todo!(),
                    Error::OutOfOrderError => {
                        self.publisher.notify(&TelNotification::OutOfOrder(event))
                    }
                    Error::MissingIssuerEventError => self
                        .publisher
                        .notify(&TelNotification::MissingIssuer(event)),
                    Error::DigestsNotMatchError => todo!(),
                    Error::MissingRegistryError => self
                        .publisher
                        .notify(&TelNotification::MissingRegistry(event)),
                    Error::UnknownIdentifierError => todo!(),
                    _ => todo!(),
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
                Err(Error::MissingIssuerEventError) => self
                    .publisher
                    .notify(&TelNotification::MissingIssuer(event)),
                Err(_) => todo!(),
            },
        }
    }
}
