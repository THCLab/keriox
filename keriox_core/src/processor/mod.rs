use std::sync::Arc;

// #[cfg(feature = "async")]
// pub mod async_processing;
pub mod basic_processor;
pub mod escrow;
pub mod event_storage;
pub mod notification;
#[cfg(test)]
mod tests;
pub mod validator;
pub mod witness_processor;

use crate::{
    database::sled::SledEventDatabase,
    error::Error,
    event::{receipt::Receipt, SerializationFormats},
    event_message::signed_event_message::{
        Message, SignedEventMessage, SignedNontransferableReceipt, TimestampedSignedEventMessage,
    },
    prefix::IdentifierPrefix,
    query::reply_event::ReplyRoute,
    state::IdentifierState,
};

use self::{
    notification::{JustNotification, Notification, NotificationBus, Notifier},
    validator::EventValidator,
};

pub trait Processor {
    fn new(db_path: Arc<SledEventDatabase>) -> Self;
    fn process(&self, message: Message) -> Result<(), Error>;
    fn register_observer(&mut self, observer: Arc<dyn Notifier + Send + Sync>)
        -> Result<(), Error>;
}

pub struct EventProcessor {
    db: Arc<SledEventDatabase>,
    validator: EventValidator,
    publisher: NotificationBus,
}

impl EventProcessor {
    pub fn new(db: Arc<SledEventDatabase>, publisher: NotificationBus) -> Self {
        let validator = EventValidator::new(db.clone());
        Self {
            db,
            validator,
            publisher,
        }
    }

    pub fn register_observer(
        &mut self,
        observer: Arc<dyn Notifier + Send + Sync>,
    ) -> Result<(), Error> {
        self.publisher
            .register_observer(observer, vec![JustNotification::KeyEventAdded]);
        Ok(())
    }

    /// Process
    ///
    /// Process a deserialized KERI message
    /// Update database based on event validation result.
    pub fn process<F>(&self, message: Message, processing_strategy: F) -> Result<(), Error>
    where
        F: Fn(Arc<SledEventDatabase>, &NotificationBus, SignedEventMessage) -> Result<(), Error>,
    {
        match message {
            Message::Event(signed_event) => {
                processing_strategy(self.db.clone(), &self.publisher, signed_event.clone())?;
                // check if receipts are attached
                if let Some(witness_receipts) = signed_event.witness_receipts {
                    // Create and process witness receipts
                    // TODO What timestamp should be set?
                    let id = signed_event.event_message.event.get_prefix();
                    let receipt = Receipt {
                        receipted_event_digest: signed_event.event_message.get_digest(),
                        prefix: id,
                        sn: signed_event.event_message.event.get_sn(),
                    };
                    let signed_receipt = SignedNontransferableReceipt::new(
                        &receipt.to_message(SerializationFormats::JSON).unwrap(),
                        None,
                        Some(witness_receipts),
                    );
                    self.process(
                        Message::NontransferableRct(signed_receipt),
                        processing_strategy,
                    )
                } else {
                    Ok(())
                }
            }
            Message::NontransferableRct(rct) => {
                let id = &rct.body.event.prefix;
                match self.validator.validate_witness_receipt(&rct) {
                    Ok(_) => {
                        self.db.add_receipt_nt(rct.to_owned(), id)?;
                        self.publisher.notify(&Notification::ReceiptAccepted)
                    }
                    Err(Error::MissingEvent) => self
                        .publisher
                        .notify(&Notification::ReceiptOutOfOrder(rct.clone())),
                    Err(e) => Err(e),
                }
            }
            Message::TransferableRct(vrc) => {
                match self.validator.validate_validator_receipt(&vrc) {
                    Ok(_) => {
                        self.db.add_receipt_t(vrc.clone(), &vrc.body.event.prefix)?;
                        self.publisher.notify(&Notification::ReceiptAccepted)
                    }
                    Err(Error::MissingEvent) | Err(Error::EventOutOfOrderError) => self
                        .publisher
                        .notify(&Notification::TransReceiptOutOfOrder(vrc.clone())),
                    Err(e) => Err(e),
                }
            }
            #[cfg(feature = "query")]
            Message::Reply(rpy) => match rpy.reply.get_route() {
                ReplyRoute::Ksn(_, _) => match self.validator.process_signed_ksn_reply(&rpy) {
                    Ok(_) => self
                        .db
                        .update_accepted_reply(rpy.clone(), &rpy.reply.get_prefix()),
                    Err(Error::EventOutOfOrderError) => {
                        self.publisher.notify(&Notification::KsnOutOfOrder(rpy))
                    }
                    Err(anything) => Err(anything),
                },
                _ => Ok(()),
            },
            #[cfg(feature = "query")]
            Message::Query(_) => {
                // TODO should do nothing?
                // It doesn't update database
                Ok(())
            }
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
