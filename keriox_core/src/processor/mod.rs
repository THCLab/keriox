use std::sync::Arc;

use crate::event_message::signed_event_message::{Message, SignedEventMessage};
#[cfg(feature = "query")]
use crate::{
    database::sled::SledEventDatabase, error::Error,
    event_message::signed_event_message::TimestampedSignedEventMessage, prefix::IdentifierPrefix,
    state::IdentifierState,
};

// #[cfg(feature = "async")]
// pub mod async_processing;
pub mod escrow;
pub mod event_processor;
pub mod event_storage;
pub mod notification;
pub mod responder;
#[cfg(test)]
mod tests;
pub mod validator;
pub mod witness_processor;

use self::{
    event_processor::{EventProcessor, Processor},
    notification::{Notification, NotificationBus},
    validator::EventValidator,
};

pub struct BasicProcessor(EventProcessor);

impl Processor for BasicProcessor {
    fn process(&self, message: Message) -> Result<(), Error> {
        self.process(message)
    }

    fn new(db: Arc<SledEventDatabase>) -> Self {
        Self::new(db)
    }
}

impl BasicProcessor {
    pub fn new(db: Arc<SledEventDatabase>) -> Self {
        let processor = EventProcessor::new(db, NotificationBus::default());
        Self(processor)
    }

    fn basic_processing_strategy(
        db: Arc<SledEventDatabase>,
        publisher: &NotificationBus,
        signed_event: SignedEventMessage,
    ) -> Result<(), Error> {
        let id = &signed_event.event_message.event.get_prefix();
        let validator = EventValidator::new(db.clone());
        match validator.validate_event(&signed_event) {
            Ok(_) => {
                db.add_kel_finalized_event(signed_event.clone(), id)?;
                publisher.notify(&Notification::KeyEventAdded(signed_event))
            }
            Err(Error::EventOutOfOrderError) => {
                publisher.notify(&Notification::OutOfOrder(signed_event))
            }
            Err(Error::NotEnoughReceiptsError) => {
                publisher.notify(&Notification::PartiallyWitnessed(signed_event))
            }
            Err(Error::NotEnoughSigsError) => {
                publisher.notify(&Notification::PartiallySigned(signed_event))
            }
            Err(Error::EventDuplicateError) => {
                db.add_duplicious_event(signed_event.clone(), id)?;
                publisher.notify(&Notification::DupliciousEvent(signed_event))
            }
            Err(e) => Err(e),
        }
    }

    /// Process
    ///
    /// Process a deserialized KERI message.
    /// Ignore not fully witness error and accept not fully witnessed events.
    pub fn process(&self, message: Message) -> Result<(), Error> {
        self.0
            .process(message, BasicProcessor::basic_processing_strategy)?;
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
