use std::{sync::Arc, time::Duration};

use keri::{
    database::escrow::{Escrow, EscrowDb},
    prefix::IdentifierPrefix,
    processor::{
        event_storage::EventStorage,
        notification::{Notification, NotificationBus, Notifier},
    },
};

use crate::{database::EventDatabase, error::Error, event::verifiable_event::VerifiableEvent};

use super::{
    notification::TelNotificationBus, storage::TelEventStorage, validator::TelEventValidator,
    TelEventProcessor,
};

pub struct MissingIssuerEscrow {
    kel_reference: Arc<EventStorage>,
    tel_reference: Arc<TelEventStorage>,
    publisher: TelNotificationBus,
    pub escrowed_missing_issuer: Escrow<VerifiableEvent>,
}

impl MissingIssuerEscrow {
    pub fn new(
        db: Arc<TelEventStorage>,
        escrow_db: Arc<EscrowDb>,
        duration: Duration,
        kel_reference: Arc<EventStorage>,
        bus: Option<TelNotificationBus>,
    ) -> Self {
        let escrow = Escrow::new(b"mie.", duration, escrow_db);
        Self {
            tel_reference: db,
            escrowed_missing_issuer: escrow,
            kel_reference,
            publisher: bus.unwrap_or_default(),
        }
    }
}
impl Notifier for MissingIssuerEscrow {
    fn notify(
        &self,
        notification: &Notification,
        _bus: &NotificationBus,
    ) -> Result<(), keri::error::Error> {
        match notification {
            Notification::KeyEventAdded(ev_message) => {
                let digest = ev_message.event_message.digest()?;

                self.process_missing_issuer_escrow(&IdentifierPrefix::SelfAddressing(digest))
                    .unwrap();
            }
            _ => {
                return Err(keri::error::Error::SemanticError(
                    "Wrong notification".into(),
                ))
            }
        }

        Ok(())
    }
}

impl MissingIssuerEscrow {
    pub fn process_missing_issuer_escrow(&self, id: &IdentifierPrefix) -> Result<(), Error> {
        if let Some(esc) = self.escrowed_missing_issuer.get(id) {
            for event in esc {
                let validator = TelEventValidator::new(
                    self.tel_reference.db.clone(),
                    self.kel_reference.clone(),
                );
                let result = match &event.event {
                    crate::event::Event::Management(man) => {
                        validator.validate_management(&man, &event.seal)
                    }
                    crate::event::Event::Vc(vc) => validator.validate_vc(&vc, &event.seal),
                };
                match result {
                    Ok(_) => {
                        // remove from escrow
                        self.escrowed_missing_issuer.remove(id, &event).unwrap();
                        // accept tel event
                        self.tel_reference
                            .db
                            .add_new_event(event.clone(), id)
                            .unwrap();
                        self.publisher.notify(
                            &super::notification::TelNotification::TelEventAdded(event.event),
                        )?;
                    }
                    Err(Error::MissingSealError) => {
                        // remove from escrow
                        self.escrowed_missing_issuer.remove(id, &event).unwrap();
                    }
                    Err(Error::OutOfOrderError) => {
                        self.escrowed_missing_issuer.remove(id, &event).unwrap();
                        self.publisher
                            .notify(&super::notification::TelNotification::OutOfOrder(event))?;
                        ()
                    }
                    Err(Error::MissingRegistryError) => {
                        self.escrowed_missing_issuer.remove(id, &event).unwrap();
                        self.publisher.notify(
                            &super::notification::TelNotification::MissingRegistry(event),
                        )?;
                        ()
                    }
                    Err(_e) => (), // keep in escrow,
                }
            }
        };

        Ok(())
    }
}
