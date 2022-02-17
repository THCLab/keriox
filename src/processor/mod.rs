use std::sync::Arc;

use crate::{
    database::sled::SledEventDatabase,
    error::Error,
    event_message::signed_event_message::{Message, TimestampedSignedEventMessage},
    prefix::IdentifierPrefix,
    state::IdentifierState,
};

#[cfg(feature = "async")]
pub mod async_processing;
pub mod escrow;
pub mod event_storage;
pub mod notification;
#[cfg(test)]
mod tests;
pub mod validator;
pub mod witness_processor;

use self::{
    notification::{JustNotification, Notification, NotificationBus},
    validator::EventValidator,
};

pub struct EventProcessor {
    db: Arc<SledEventDatabase>,
    validator: EventValidator,
    escrows: NotificationBus,
}

impl EventProcessor {
    pub fn with_default_escrow(db: Arc<SledEventDatabase>) -> Self {
        let bus = escrow::default_escrow_bus(db.clone());
        EventProcessor::new(db, Some(bus))
    }

    pub fn new(db: Arc<SledEventDatabase>, bus: Option<NotificationBus>) -> Self {
        let validator = EventValidator::new(db.clone());
        Self {
            db,
            validator,
            escrows: bus.unwrap_or_default(),
        }
    }

    /// Process
    ///
    /// Process a deserialized KERI message
    /// Update database based on event validation result.
    pub fn process(&self, message: Message) -> Result<(), Error> {
        match message {
            Message::Event(signed_event) => {
                let id = &signed_event.event_message.event.get_prefix();
                match self.validator.validate_event(&signed_event) {
                    Ok(_) => {
                        self.db.add_kel_finalized_event(signed_event.clone(), id)?;
                        self.escrows
                            .notify(&Notification::KeyEventAdded(signed_event))
                    }
                    Err(e) => {
                        match e {
                            Error::EventDuplicateError => {
                                self.db.add_duplicious_event(signed_event.clone(), id)
                            }
                            Error::EventOutOfOrderError => {
                                self.escrows.notify(&Notification::OutOfOrder(signed_event))
                            }
                            Error::NotEnoughReceiptsError => self
                                .escrows
                                .notify(&Notification::PartiallyWitnessed(signed_event)),
                            Error::NotEnoughSigsError => self
                                .escrows
                                .notify(&Notification::PartiallySigned(signed_event)),
                            _ => Ok(()),
                        }?;
                        Err(e)
                    }
                }?;
            }

            Message::NontransferableRct(rct) => {
                let id = &rct.body.event.prefix;
                match self.validator.validate_witness_receipt(&rct) {
                    Ok(_) => {
                        self.db.add_receipt_nt(rct.to_owned(), id)?;
                        self.escrows.notify(&Notification::ReceiptAccepted)
                    }
                    Err(Error::MissingEvent) => self
                        .escrows
                        .notify(&Notification::ReceiptOutOfOrder(rct.clone())),
                    Err(e) => return Err(e),
                }?;
            }
            Message::TransferableRct(vrc) => {
                match self.validator.validate_validator_receipt(&vrc) {
                    Ok(_) => self.db.add_receipt_t(vrc.clone(), &vrc.body.event.prefix),
                    Err(Error::MissingEvent) => self
                        .escrows
                        .notify(&Notification::TransReceiptOutOfOrder(vrc.clone())),
                    Err(e) => Err(e),
                }?;
            }
            #[cfg(feature = "query")]
            Message::KeyStateNotice(rpy) => {
                match self.validator.process_signed_reply(&rpy) {
                    Ok(_) => {
                        self.db
                            .update_accepted_reply(rpy.clone(), &rpy.reply.event.get_prefix())?;
                        self.escrows.notify(&Notification::ReplyUpdated)
                    }
                    Err(Error::EventOutOfOrderError) => {
                        self.escrows.notify(&Notification::ReplyOutOfOrder(rpy))?;
                        Err(Error::EventOutOfOrderError)
                    }
                    Err(anything) => Err(anything),
                }?;
            }
            #[cfg(feature = "query")]
            Message::Query(_qry) => todo!(),
        }
        Ok(())
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
