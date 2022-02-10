use std::sync::Arc;

use crate::{
    database::sled::SledEventDatabase,
    error::Error,
    event_message::signed_event_message::{Message, TimestampedSignedEventMessage},
    prefix::IdentifierPrefix,
    processor::escrow::PartiallySignedEscrow,
    state::IdentifierState,
};

#[cfg(feature = "async")]
pub mod async_processing;
pub mod escrow;
pub mod event_storage;
#[cfg(test)]
mod tests;
pub mod validator;
pub mod witness_processor;

use self::{
    escrow::{Escrow, Notification},
    validator::EventValidator,
};

pub struct EventProcessor {
    db: Arc<SledEventDatabase>,
    validator: EventValidator,
    escrows: Vec<Box<dyn Escrow>>,
}

impl EventProcessor {
    pub fn with_default_escrow(db: Arc<SledEventDatabase>) -> Self {
        use self::escrow::{NontransReceiptsEscrow, OutOfOrderEscrow, PartiallyWitnessedEscrow};
        let mut processor = EventProcessor::new(db);
        processor.register_escrow(Box::new(OutOfOrderEscrow::default()));
        processor.register_escrow(Box::new(PartiallySignedEscrow::default()));
        processor.register_escrow(Box::new(PartiallyWitnessedEscrow::default()));
        processor.register_escrow(Box::new(NontransReceiptsEscrow::default()));
        processor
    }

    pub fn new(db: Arc<SledEventDatabase>) -> Self {
        let validator = EventValidator::new(db.clone());
        let escrows: Vec<Box<dyn Escrow>> = Vec::new();

        Self {
            db,
            validator,
            escrows,
        }
    }

    pub fn register_escrow(&mut self, escrow: Box<dyn Escrow>) {
        self.escrows.push(escrow);
    }

    pub fn notify(&self, notification: &Notification) -> Result<(), Error> {
        self.escrows.iter().for_each(|esc| {
            esc.notify(notification, self).unwrap();
        });
        Ok(())
    }

    /// Process
    ///
    /// Process a deserialized KERI message
    pub fn process(&self, message: Message) -> Result<Option<IdentifierState>, Error> {
        match message {
            Message::Event(signed_event) => {
                let id = &signed_event.event_message.event.get_prefix();
                match self.validator.process_event(&signed_event) {
                    Ok(_) => {
                        self.db.add_kel_finalized_event(signed_event.clone(), id)?;
                        self.notify(&Notification::KelUpdated(id.clone()))
                    }
                    Err(e) => {
                        match e {
                            Error::EventDuplicateError => {
                                self.db.add_duplicious_event(signed_event.clone(), id)
                            }
                            Error::EventOutOfOrderError => {
                                self.notify(&Notification::OutOfOrder(signed_event))
                            }
                            Error::NotEnoughReceiptsError => {
                                self.notify(&Notification::PartiallyWitnessed(signed_event))
                            }
                            Error::NotEnoughSigsError => {
                                self.notify(&Notification::PartiallySigned(signed_event))
                            }
                            _ => Ok(()),
                        }?;
                        Err(e)
                    }
                }?;
                Ok(compute_state(self.db.clone(), id)?)
            }

            Message::NontransferableRct(rct) => {
                let id = &rct.body.event.prefix;
                match self.validator.process_witness_receipt(&rct) {
                    Ok(_) => {
                        self.db.add_receipt_nt(rct.to_owned(), id)?;
                        self.notify(&Notification::ReceiptAccepted(rct.clone()))
                    }
                    Err(Error::MissingEvent) => {
                        self.notify(&Notification::ReceiptOutOfOrder(rct.clone()))
                    }
                    Err(e) => return Err(e),
                }?;
                Ok(compute_state(self.db.clone(), id)?)
            }
            Message::TransferableRct(vrc) => {
                match self.validator.process_validator_receipt(&vrc) {
                    Ok(_) => self.db.add_receipt_t(vrc.clone(), &vrc.body.event.prefix),
                    Err(Error::MissingEvent) => {
                        self.notify(&Notification::TransReceiptOutOfOrder(vrc.clone()))
                    }
                    Err(e) => Err(e),
                }?;
                let id = vrc.body.event.prefix;
                Ok(compute_state(self.db.clone(), &id)?)
            }
            #[cfg(feature = "query")]
            Message::KeyStateNotice(rpy) => {
                match self.validator.process_signed_reply(&rpy) {
                    Ok(_) => {
                        self.db
                            .update_accepted_reply(rpy.clone(), &rpy.reply.event.get_prefix())?;
                        self.notify(&Notification::ReplyUpdated)
                    }
                    Err(Error::EventOutOfOrderError) => {
                        self.notify(&Notification::ReplyOutOfOrder(rpy))?;
                        Err(Error::EventOutOfOrderError)
                    }
                    Err(anything) => Err(anything),
                }?;
                Ok(None)
            }
            #[cfg(feature = "query")]
            Message::Query(_qry) => todo!(),
        }
    }
}

/// Compute State for Prefix
///
/// Returns the current State associated with
/// the given Prefix
pub fn compute_state(
    db: Arc<SledEventDatabase>,
    id: &IdentifierPrefix,
) -> Result<Option<IdentifierState>, Error> {
    if let Some(events) = db.get_kel_finalized_events(id) {
        // start with empty state
        let mut state = IdentifierState::default();
        // we sort here to get inception first
        let mut sorted_events = events.collect::<Vec<TimestampedSignedEventMessage>>();
        // TODO why identifier is in database if there are no events for it?
        if sorted_events.is_empty() {
            return Ok(None);
        };
        sorted_events.sort();
        for event in sorted_events {
            state = match state.clone().apply(&event.signed_event_message) {
                Ok(s) => s,
                // will happen when a recovery has overridden some part of the KEL,
                Err(e) => match e {
                    // skip out of order and partially signed events
                    Error::EventOutOfOrderError | Error::NotEnoughSigsError => continue,
                    // stop processing here
                    _ => break,
                },
            };
        }
        Ok(Some(state))
    } else {
        // no inception event, no state
        Ok(None)
    }
}
