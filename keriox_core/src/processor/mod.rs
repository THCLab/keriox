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

use said::version::format::SerializationFormats;

use self::{
    notification::{JustNotification, Notification, NotificationBus, Notifier},
    validator::EventValidator,
};
#[cfg(feature = "query")]
use crate::query::reply_event::{ReplyRoute, SignedReply};
use crate::{
    database::{timestamped::TimestampedSignedEventMessage, EventDatabase},
    error::Error,
    event::receipt::Receipt,
    event_message::signed_event_message::{
        Notice, SignedEventMessage, SignedNontransferableReceipt,
    },
    prefix::IdentifierPrefix,
    state::IdentifierState,
};

pub trait Processor {
    type Database: EventDatabase + 'static;
    fn process_notice(&self, notice: &Notice) -> Result<(), Error>;

    #[cfg(feature = "query")]
    fn process_op_reply(&self, reply: &SignedReply) -> Result<(), Error>;

    fn register_observer(
        &self,
        observer: Arc<dyn Notifier + Send + Sync>,
        notifications: &[JustNotification],
    ) -> Result<(), Error>;

    fn process(
        &self,
        msg: &crate::event_message::signed_event_message::Message,
    ) -> Result<(), Error> {
        use crate::event_message::signed_event_message::Message;
        #[cfg(feature = "query")]
        use crate::event_message::signed_event_message::Op;
        match msg {
            Message::Notice(notice) => self.process_notice(notice),
            #[cfg(any(feature = "query", feature = "oobi"))]
            Message::Op(op) => match op {
                #[cfg(feature = "query")]
                Op::Query(_query) => panic!("processor can't handle query op"),
                #[cfg(feature = "query")]
                Op::Reply(reply) => self.process_op_reply(reply),
                _ => todo!(),
            },
        }
    }
}

pub struct EventProcessor<D: EventDatabase> {
    events_db: Arc<D>,
    validator: EventValidator<D>,
    publisher: NotificationBus,
}

/* impl EventProcessor<RedbDatabase> {
    pub fn new(publisher: NotificationBus, events_db: Arc<RedbDatabase>) -> Self {
        let validator = EventValidator::new(events_db.clone());
        Self {
            events_db,
            validator,
            publisher,
        }
    }
} */

impl<D: EventDatabase + 'static> EventProcessor<D> {
    pub fn new(publisher: NotificationBus, events_db: Arc<D>) -> Self {
        let validator = EventValidator::new(events_db.clone());
        Self {
            events_db,
            validator,
            publisher,
        }
    }

    pub fn register_observer(
        &self,
        observer: Arc<dyn Notifier + Send + Sync>,
        notifications: Vec<JustNotification>,
    ) -> Result<(), Error> {
        self.publisher.register_observer(observer, notifications);
        Ok(())
    }

    #[cfg(feature = "query")]
    pub fn process_op_reply(&self, rpy: &SignedReply) -> Result<(), Error> {
        use crate::processor::validator::MoreInfoError;

        use self::validator::VerificationError;

        match rpy.reply.get_route() {
            ReplyRoute::Ksn(_, _) => match self.validator.process_signed_ksn_reply(rpy) {
                Ok(_) => {
                    self.events_db
                        .save_reply(rpy.clone())
                        .map_err(|_e| Error::DbError)?;
                }
                Err(Error::VerificationError(VerificationError::MoreInfo(
                    MoreInfoError::EventNotFound(_),
                ))) => {
                    self.publisher
                        .notify(&Notification::KsnOutOfOrder(rpy.clone()))?;
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
        F: Fn(
            Arc<D>,
            // Arc<SledEventDatabase>,
            &NotificationBus,
            SignedEventMessage,
        ) -> Result<(), Error>,
    {
        match notice {
            Notice::Event(signed_event) => {
                processing_strategy(
                    self.events_db.clone(),
                    // self.db.clone(),
                    &self.publisher,
                    signed_event.clone(),
                )?;
                // check if receipts are attached
                if let Some(witness_receipts) = &signed_event.witness_receipts {
                    // Create and process witness receipts
                    let id = signed_event.event_message.data.get_prefix();
                    let receipt = Receipt::new(
                        SerializationFormats::JSON,
                        signed_event.event_message.digest()?,
                        id,
                        signed_event.event_message.data.get_sn(),
                    );
                    let signed_receipt =
                        SignedNontransferableReceipt::new(&receipt, witness_receipts.clone());
                    self.process_notice(
                        &Notice::NontransferableRct(signed_receipt),
                        processing_strategy,
                    )
                } else {
                    Ok(())
                }
            }
            Notice::NontransferableRct(rct) => {
                let id = &rct.body.prefix;
                match self.validator.validate_witness_receipt(rct) {
                    Ok(_) => {
                        self.events_db
                            .add_receipt_nt(rct.to_owned(), id)
                            .map_err(|_| Error::DbError)?;
                        self.publisher.notify(&Notification::ReceiptAccepted)
                    }
                    Err(Error::MissingEvent) => self
                        .publisher
                        .notify(&Notification::ReceiptOutOfOrder(rct.clone())),
                    Err(e) => Err(e),
                }
            }
            Notice::TransferableRct(vrc) => match self.validator.validate_validator_receipt(vrc) {
                Ok(_) => {
                    self.events_db
                        .add_receipt_t(vrc.clone(), &vrc.body.prefix)
                        .map_err(|_| Error::DbError)?;
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
pub fn compute_state<D: EventDatabase>(
    db: Arc<D>,
    id: &IdentifierPrefix,
) -> Option<IdentifierState> {
    if let Some(events) = db.get_kel_finalized_events(crate::database::QueryParameters::All { id })
    {
        // start with empty state
        let mut state = IdentifierState::default();
        // we sort here to get inception first
        let mut sorted_events = events.collect::<Vec<TimestampedSignedEventMessage>>();
        // TODO why identifier is in database if there are no events for it?
        if sorted_events.is_empty() {
            return None;
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
        Some(state)
    } else {
        // no inception event, no state
        None
    }
}
