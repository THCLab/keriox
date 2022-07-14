use std::sync::Arc;

pub mod basic_processor;
pub mod escrow;
#[cfg(test)]
mod escrow_tests;
pub mod event_storage;
pub mod notification;
#[cfg(test)]
mod processor_tests;

pub mod validator;

use self::{
    notification::{JustNotification, Notification, NotificationBus, Notifier},
    validator::EventValidator,
};
use crate::{
    database::{timestamped::TimestampedSignedEventMessage, SledEventDatabase},
    error::Error,
    event::{receipt::Receipt, SerializationFormats},
    event_message::signed_event_message::{
        Notice, SignedEventMessage, SignedNontransferableReceipt,
    },
    prefix::IdentifierPrefix,
    query::reply_event::{ReplyRoute, SignedReply},
    state::IdentifierState,
};

pub trait Processor {
    fn process_notice(&self, notice: &Notice) -> Result<(), Error>;

    #[cfg(feature = "query")]
    fn process_op_reply(&self, reply: &SignedReply) -> Result<(), Error>;

    fn register_observer(
        &mut self,
        observer: Arc<dyn Notifier + Send + Sync>,
        notifications: &[JustNotification],
    ) -> Result<(), Error>;

    fn process(
        &self,
        msg: &crate::event_message::signed_event_message::Message,
    ) -> Result<(), Error> {
        use crate::event_message::signed_event_message::{Message, Op};

        match msg {
            Message::Notice(notice) => self.process_notice(notice),
            Message::Op(op) => match op {
                Op::Query(_query) => panic!("processor can't handle query op"),
                Op::Reply(reply) => self.process_op_reply(reply),
            },
        }
    }
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
        notifications: Vec<JustNotification>,
    ) -> Result<(), Error> {
        self.publisher.register_observer(observer, notifications);
        Ok(())
    }

    #[cfg(feature = "query")]
    pub fn process_op_reply(&self, rpy: &SignedReply) -> Result<(), Error> {
        match rpy.reply.get_route() {
            ReplyRoute::Ksn(_, _) => match self.validator.process_signed_ksn_reply(&rpy) {
                Ok(_) => {
                    self.db
                        .update_accepted_reply(rpy.clone(), &rpy.reply.get_prefix())?;
                }
                Err(Error::EventOutOfOrderError) => {
                    self.publisher
                        .notify(&Notification::KsnOutOfOrder(rpy.clone()))?;
                }
                Err(anything) => return Err(anything),
            },
            _ => {}
        }
        Ok(())
    }

    pub fn process_notice<F>(&self, notice: &Notice, processing_strategy: F) -> Result<(), Error>
    where
        F: Fn(Arc<SledEventDatabase>, &NotificationBus, SignedEventMessage) -> Result<(), Error>,
    {
        match notice {
            Notice::Event(signed_event) => {
                processing_strategy(self.db.clone(), &self.publisher, signed_event.clone())?;
                // check if receipts are attached
                if let Some(witness_receipts) = &signed_event.witness_receipts {
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
                        Some(witness_receipts.clone()),
                    );
                    self.process_notice(
                        &Notice::NontransferableRct(signed_receipt),
                        processing_strategy,
                    )
                } else {
                    Ok(())
                }
            }
            Notice::NontransferableRct(rct) => {
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
            Notice::TransferableRct(vrc) => match self.validator.validate_validator_receipt(&vrc) {
                Ok(_) => {
                    self.db.add_receipt_t(vrc.clone(), &vrc.body.event.prefix)?;
                    self.publisher.notify(&Notification::ReceiptAccepted)
                }
                Err(Error::MissingEvent) | Err(Error::EventOutOfOrderError) => self
                    .publisher
                    .notify(&Notification::TransReceiptOutOfOrder(vrc.clone())),
                Err(e) => Err(e),
            },
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
