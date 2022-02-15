use std::{sync::Arc, collections::HashMap};

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
    escrow::{Notifier, Notification},
    validator::EventValidator,
};

#[derive(PartialEq, Hash, Eq)]
pub enum JustNotification {
    KeyEventAdded,
    OutOfOrder,
    PartiallySigned,
    PartiallyWitnessed,
    ReceiptAccepted,
    ReceiptEscrowed,
    ReceiptOutOfOrder,
    TransReceiptOutOfOrder,
    #[cfg(feature = "query")]
    ReplyOutOfOrder,
    #[cfg(feature = "query")]
    ReplyUpdated,
}

impl Into<JustNotification> for &Notification {
    fn into(self) -> JustNotification {
         match self {
            Notification::KeyEventAdded(_) => JustNotification::KeyEventAdded,
            Notification::OutOfOrder(_) => JustNotification::OutOfOrder,
            Notification::PartiallySigned(_) => JustNotification::PartiallySigned,
            Notification::PartiallyWitnessed(_) => JustNotification::PartiallyWitnessed,
            Notification::ReceiptAccepted => JustNotification::ReceiptAccepted,
            Notification::ReceiptEscrowed => JustNotification::ReceiptEscrowed,
            Notification::ReceiptOutOfOrder(_) => JustNotification::ReceiptOutOfOrder,
            Notification::TransReceiptOutOfOrder(_) => JustNotification::TransReceiptOutOfOrder,
            #[cfg(feature = "query")]
            Notification::ReplyOutOfOrder(_) => JustNotification::ReplyOutOfOrder,
            #[cfg(feature = "query")]
            Notification::ReplyUpdated => JustNotification::ReplyUpdated,
        }
    }
}

pub struct EventProcessor {
    db: Arc<SledEventDatabase>,
    validator: EventValidator,
    escrows: HashMap<JustNotification, Vec<Box<dyn Notifier>>>,
}

impl EventProcessor {
    pub fn with_default_escrow(db: Arc<SledEventDatabase>) -> Self {
        use self::escrow::{NontransReceiptsEscrow, OutOfOrderEscrow, PartiallyWitnessedEscrow};
        let mut processor = EventProcessor::new(db.clone());
        processor.register_observer(OutOfOrderEscrow::new(db.clone()), vec![JustNotification::OutOfOrder, JustNotification::KeyEventAdded]);
        processor.register_observer(PartiallySignedEscrow::new(db.clone()), vec![JustNotification::PartiallySigned]);
        processor.register_observer(PartiallyWitnessedEscrow::new(db.clone()), vec![JustNotification::PartiallyWitnessed, JustNotification::ReceiptEscrowed, JustNotification::ReceiptAccepted]);
        processor.register_observer(NontransReceiptsEscrow::new(db), vec![JustNotification::KeyEventAdded, JustNotification::ReceiptOutOfOrder]);
        processor
    }

    pub fn new(db: Arc<SledEventDatabase>) -> Self {
        let validator = EventValidator::new(db.clone());
        let escrows: HashMap<JustNotification, Vec<Box<dyn Notifier>>> = HashMap::new();

        Self {
            db,
            validator,
            escrows,
        }
    }

    pub fn register_observer<N: Notifier + Clone + 'static>(&mut self, escrow: N, notification: Vec<JustNotification>) {
        notification.into_iter().for_each(|notification| {
		    self.escrows.entry(notification).or_insert(vec![]).push(Box::new(escrow.clone()));
            }
        );
    }

    pub fn notify(&self, notification: &Notification) -> Result<(), Error> {
        self.escrows.get(&notification.into()).unwrap_or(&Box::new(vec![])).iter().for_each(|esc| {
            esc.notify(notification, self).unwrap();
        });
        Ok(())
    }

    /// Process
    ///
    /// Process a deserialized KERI message
    /// Update database based on event validation result.
    pub fn process(&self, message: Message) -> Result<Option<IdentifierState>, Error> {
        match message {
            Message::Event(signed_event) => {
                let id = &signed_event.event_message.event.get_prefix();
                match self.validator.validate_event(&signed_event) {
                    Ok(_) => {
                        self.db.add_kel_finalized_event(signed_event.clone(), id)?;
                        self.notify(&Notification::KeyEventAdded(id.clone()))
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
                match self.validator.validate_witness_receipt(&rct) {
                    Ok(_) => {
                        self.db.add_receipt_nt(rct.to_owned(), id)?;
                        self.notify(&Notification::ReceiptAccepted)
                    }
                    Err(Error::MissingEvent) => {
                        self.notify(&Notification::ReceiptOutOfOrder(rct.clone()))
                    }
                    Err(e) => return Err(e),
                }?;
                Ok(compute_state(self.db.clone(), id)?)
            }
            Message::TransferableRct(vrc) => {
                match self.validator.validate_validator_receipt(&vrc) {
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
