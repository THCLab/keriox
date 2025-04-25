use std::{sync::Arc, time::Duration};

use crate::{actor::prelude::SledEventDatabase, database::{redb::{escrow_database::SnKeyDatabase, RedbDatabase}, EventDatabase}, error::Error, event::KeyEvent, event_message::{msg::KeriEvent, signed_event_message::SignedEventMessage}, processor::{notification::{Notification, NotificationBus, Notifier}, validator::EventValidator}};

use super::maybe_out_of_order_escrow::SnKeyEscrow;


pub struct PartiallySignedEscrow<D: EventDatabase> {
    db: Arc<D>,
    old_db: Arc<SledEventDatabase>,
    pub escrowed_partially_signed: SnKeyEscrow,
}

impl PartiallySignedEscrow<RedbDatabase> {
    pub fn new(
        db: Arc<RedbDatabase>,
        sled_db: Arc<SledEventDatabase>,
        _duration: Duration,
    ) -> Self {
        let escrow_db = SnKeyEscrow::new(
            Arc::new(SnKeyDatabase::new(db.db.clone(), "partially_signed_escrow").unwrap()),
            db.log_db.clone(),
        );
        Self {
            db,
            old_db: sled_db,
            escrowed_partially_signed: escrow_db,
        }
    }
}

impl<D: EventDatabase> PartiallySignedEscrow<D> {
    pub fn get_partially_signed_for_event(
        &self,
        event: KeriEvent<KeyEvent>,
    ) -> Option<SignedEventMessage> {
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
}

impl<D: EventDatabase> Notifier for PartiallySignedEscrow<D> {
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

impl<D: EventDatabase> PartiallySignedEscrow<D> {
    pub fn process_partially_signed_events(
        &self,
        bus: &NotificationBus,
        signed_event: &SignedEventMessage,
    ) -> Result<(), Error> {
        let id = signed_event.event_message.data.get_prefix();
        let sn = signed_event.event_message.data.sn;
        if let Some(esc) = self
            .escrowed_partially_signed
            .get(&id, sn)?
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

            let validator = EventValidator::new(self.old_db.clone(), self.db.clone());
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
                    self.escrowed_partially_signed.insert(&to_add)?;
                }
                Err(_e) => {
                    // keep in escrow
                }
            }
        } else {
            self.escrowed_partially_signed
                .insert(signed_event)?;
        };

        Ok(())
    }
}
