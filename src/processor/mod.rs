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
#[cfg(test)]
mod tests;
pub mod validator;
pub mod witness_processor;

#[cfg(feature = "query")]
use crate::query::{reply::SignedReply, QueryError};

use self::validator::EventValidator;

pub struct EventProcessor {
    db: Arc<SledEventDatabase>,
    validator: EventValidator,
}

impl EventProcessor {
    pub fn new(db: Arc<SledEventDatabase>) -> Self {
        let validator = EventValidator::new(db.clone());
        Self { db, validator }
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
                        // self.process_nt_receipts_escrow()
                        escrow::process_nt_receipts_escrow(self)?;
                        escrow::process_out_of_order_events(self, id)
                    }
                    Err(e) => {
                        match e {
                            Error::EventDuplicateError => {
                                self.db.add_duplicious_event(signed_event.clone(), id)
                            }
                            Error::EventOutOfOrderError => {
                                self.db.add_out_of_order_event(signed_event, id)
                            }
                            Error::NotEnoughReceiptsError => self
                                .db
                                .add_partially_witnessed_event(signed_event.clone(), id),
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
                    Ok(_) => self.db.add_receipt_nt(rct.to_owned(), id)?,
                    Err(Error::MissingEvent) => {
                        self.db.add_escrow_nt_receipt(rct.to_owned(), id)?
                    }
                    Err(e) => return Err(e),
                };
                escrow::process_partially_witnessed_events(self)?;
                Ok(compute_state(self.db.clone(), id)?)
            }
            Message::TransferableRct(vrc) => {
                match self.validator.process_validator_receipt(&vrc) {
                    Ok(_) => self.db.add_receipt_t(vrc.clone(), &vrc.body.event.prefix),
                    Err(Error::MissingEvent) => self
                        .db
                        .add_escrow_t_receipt(vrc.clone(), &vrc.body.event.prefix),
                    Err(e) => Err(e),
                }?;
                let id = vrc.body.event.prefix;
                Ok(compute_state(self.db.clone(), &id)?)
            }
            #[cfg(feature = "query")]
            Message::KeyStateNotice(rpy) => {
                match self.validator.process_signed_reply(&rpy) {
                    Ok(_) => self
                        .db
                        .update_accepted_reply(rpy.clone(), &rpy.reply.event.get_prefix()),
                    Err(Error::EventOutOfOrderError) => {
                        self.escrow_reply(&rpy)?;
                        Err(Error::QueryError(QueryError::OutOfOrderEventError))
                    }
                    Err(Error::QueryError(QueryError::OutOfOrderEventError)) => {
                        self.escrow_reply(&rpy)?;
                        Err(Error::QueryError(QueryError::OutOfOrderEventError))
                    }
                    Err(anything) => Err(anything),
                }?;
                Ok(None)
            }
            #[cfg(feature = "query")]
            Message::Query(_qry) => todo!(),
        }
    }

    #[cfg(feature = "query")]
    fn escrow_reply(&self, rpy: &SignedReply) -> Result<(), Error> {
        let id = rpy.reply.event.get_prefix();
        self.db.add_escrowed_reply(rpy.clone(), &id)
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
