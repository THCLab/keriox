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

use super::TelEventProcessor;

pub struct MissingIssuerEscrow {
    kel_reference: Arc<EventStorage>,
    tel_reference: TelEventProcessor,
    pub escrowed_missing_issuer: Escrow<VerifiableEvent>,
}

impl MissingIssuerEscrow {
    pub fn new(
        db: Arc<EventDatabase>,
        escrow_db: Arc<EscrowDb>,
        duration: Duration,
        kel_reference: Arc<EventStorage>,
    ) -> Self {
        let escrow = Escrow::new(b"mie.", duration, escrow_db);
        Self {
            tel_reference: TelEventProcessor::new(kel_reference, db),
            escrowed_missing_issuer: escrow,
            kel_reference,
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

                self.process_missing_issuer_escrow(&IdentifierPrefix::SelfAddressing(digest))?;
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
    pub fn process_missing_issuer_escrow(
        &self,
        id: &IdentifierPrefix,
    ) -> Result<(), keri::error::Error> {
        if let Some(esc) = self.escrowed_missing_issuer.get(id) {
            for event in esc {
                let event_processor =
                    TelEventProcessor::new(self.kel_reference.clone(), self.tel_reference.clone());
                match event_processor.process(event.clone()) {
                    Ok(_) => {
                        // remove from escrow
                        self.escrowed_missing_issuer.remove(id, &event)?;
                        // accept tel event
                        self.tel_reference.process(event).unwrap()
                    }
                    Err(Error::MissingSealError) => {
                        // remove from escrow
                        self.escrowed_missing_issuer.remove(id, &event)?;
                    }
                    Err(_e) => (), // keep in escrow,
                }
            }
        };

        Ok(())
    }
}
