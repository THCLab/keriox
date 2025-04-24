use std::{sync::Arc, time::Duration};

use crate::{actor::prelude::SledEventDatabase, database::{escrow::{Escrow, EscrowDb}, EventDatabase}, error::Error, event::KeyEvent, event_message::{msg::KeriEvent, signed_event_message::SignedEventMessage}, processor::{notification::{Notification, NotificationBus, Notifier}, validator::EventValidator}};


pub struct PartiallySignedEscrow<D: EventDatabase> {
    db: Arc<D>,
    old_db: Arc<SledEventDatabase>,
    pub escrowed_partially_signed: Escrow<SignedEventMessage>,
}

impl<D: EventDatabase> PartiallySignedEscrow<D> {
    pub fn new(
        db: Arc<D>,
        sled_db: Arc<SledEventDatabase>,
        escrow_db: Arc<EscrowDb>,
        duration: Duration,
    ) -> Self {
        let escrow = Escrow::new(b"pses", duration, escrow_db);
        Self {
            db,
            old_db: sled_db,
            escrowed_partially_signed: escrow,
        }
    }
}

impl<D: EventDatabase> PartiallySignedEscrow<D> {
    pub fn get_partially_signed_for_event(
        &self,
        event: KeriEvent<KeyEvent>,
    ) -> Option<impl DoubleEndedIterator<Item = SignedEventMessage>> {
        let id = event.data.get_prefix();
        self.escrowed_partially_signed
            .get(&id)
            .map(|events| events.filter(move |ev| ev.event_message == event))
    }

    fn remove_partially_signed(&self, event: &KeriEvent<KeyEvent>) -> Result<(), Error> {
        let id = event.data.get_prefix();
        self.escrowed_partially_signed.get(&id).map(|events| {
            events
                .filter(|ev| &ev.event_message == event)
                .try_for_each(|ev| self.escrowed_partially_signed.remove(&id, &ev))
        });
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
        if let Some(esc) = self
            .escrowed_partially_signed
            .get(&id)
            .map(|events| events.filter(|event| event.event_message == signed_event.event_message))
        {
            let mut signatures = esc.flat_map(|ev| ev.signatures).collect::<Vec<_>>();
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
                    //keep in escrow and save new partially signed event
                    let to_add = SignedEventMessage {
                        signatures: without_duplicates,
                        ..signed_event.to_owned()
                    };
                    self.escrowed_partially_signed.add(&id, to_add)?;
                }
                Err(_e) => {
                    // keep in escrow
                }
            }
        } else {
            self.escrowed_partially_signed
                .add(&id, signed_event.clone())?;
        };

        Ok(())
    }
}
