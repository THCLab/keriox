use std::{sync::Arc, time::Duration};

use keri::{
    database::escrow::{Escrow, EscrowDb},
    prefix::IdentifierPrefix,
    processor::{
        event_storage::EventStorage,
        notification::{Notification, NotificationBus, Notifier},
    },
};

use crate::{
    error::Error,
    event::{verifiable_event::VerifiableEvent, Event},
};

use super::{
    notification::{TelNotification, TelNotificationBus, TelNotifier},
    storage::TelEventStorage,
    validator::TelEventValidator,
};

pub struct MissingIssuerEscrow {
    kel_reference: Arc<EventStorage>,
    tel_reference: Arc<TelEventStorage>,
    publisher: TelNotificationBus,
    escrowed_missing_issuer: Escrow<VerifiableEvent>,
}

impl MissingIssuerEscrow {
    pub fn new(
        db: Arc<TelEventStorage>,
        escrow_db: Arc<EscrowDb>,
        duration: Duration,
        kel_reference: Arc<EventStorage>,
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

impl TelNotifier for MissingIssuerEscrow {
    fn notify(
        &self,
        notification: &super::notification::TelNotification,
        _bus: &TelNotificationBus,
    ) -> Result<(), Error> {
        match notification {
            TelNotification::MissingIssuer(event) => {
                let missing_event_digest =
                    IdentifierPrefix::SelfAddressing(event.seal.seal.digest.clone());
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
                            .notify(&TelNotification::TelEventAdded(event.event))?;
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
