use std::sync::Arc;

use crate::{
    database::sled::SledEventDatabase,
    error::Error,
    event::{event_data::EventData, sections::seal::EventSeal},
    event_message::signed_event_message::{Message, TimestampedSignedEventMessage},
    prefix::IdentifierPrefix,
    state::{IdentifierState, EventSemantics},
};

#[cfg(feature = "async")]
pub mod async_processing;
#[cfg(test)]
mod tests;
pub mod validator;

#[cfg(feature = "query")]
use crate::query::{reply::SignedReply, QueryError};

use self::validator::EventValidator;

pub struct EventProcessor {
    pub db: Arc<SledEventDatabase>,
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
                        self.process_nt_receipts_escrow()
                    }
                    Err(e) => {
                        match e {
                            Error::EventDuplicateError => {
                                self.db.add_duplicious_event(signed_event.clone(), id)
                            }
                            Error::NotEnoughReceiptsError => self
                                .db
                                .add_partially_witnessed_event(signed_event.clone(), id),
                            _ => Ok(()),
                        }?;
                        Err(e)
                    }
                }?;
                Ok(self.validator.compute_state(id)?)
            }

            Message::NontransferableRct(rct) => {
                let id = &rct.body.event.prefix.to_owned();
                match self.validator.process_witness_receipt(&rct) {
                    Ok(_) => self.db.add_receipt_nt(rct.to_owned(), id)?,
                    Err(Error::MissingEvent) => {
                        self.db.add_escrow_nt_receipt(rct.to_owned(), id)?
                    }
                    Err(e) => Err(e)?,
                };
                self.process_partially_witnessed_events()?;
                Ok(self.validator.compute_state(id)?)
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
                Ok(self.validator.compute_state(&id)?)
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

    pub fn process_nt_receipts_escrow(&self) -> Result<(), Error> {
        if let Some(esc) = self.db.get_all_escrow_nt_receipts() {
            esc.for_each(|sig_receipt| {
                match self.validator.process_witness_receipt(&sig_receipt) {
                    Ok(_) | Err(Error::SignatureVerificationError) => {
                        // remove from escrow
                        self.db
                            .remove_escrow_nt_receipt(&sig_receipt.body.event.prefix, &sig_receipt)
                            .unwrap();
                    }
                    Err(_e) => {} // keep in escrow,
                }
            })
        };

        Ok(())
    }

    pub fn process_partially_witnessed_events(&self) -> Result<(), Error> {
        if let Some(esc) = self.db.get_all_partially_witnessed() {
            esc.for_each(|event| {
                match self.process(Message::Event(event.signed_event_message.clone())) {
                    Ok(_) | Err(Error::SignatureVerificationError) => {
                        // remove from escrow
                        self.db
                            .remove_parially_witnessed_event(
                                &event.signed_event_message.event_message.event.get_prefix(),
                                &event.signed_event_message,
                            )
                            .unwrap();
                    }
                    Err(_e) => {} // keep in escrow,
                }
            })
        };

        Ok(())
    }

    #[cfg(feature = "query")]
    fn escrow_reply(&self, rpy: &SignedReply) -> Result<(), Error> {
        let id = rpy.reply.event.get_prefix();
        self.db.add_escrowed_reply(rpy.clone(), &id)
    }

    #[cfg(feature = "query")]
    pub fn process_reply_escrow(&self) -> Result<(), Error> {
        self.db.get_all_escrowed_replys().map(|esc| {
            esc.for_each(|sig_rep| {
                match self.validator.process_signed_reply(&sig_rep) {
                    Ok(_)
                    | Err(Error::SignatureVerificationError)
                    | Err(Error::QueryError(QueryError::StaleRpy)) => {
                        // remove from escrow
                        self.db
                            .remove_escrowed_reply(&sig_rep.reply.event.get_prefix(), sig_rep)
                            .unwrap();
                    }
                    Err(_e) => {} // keep in escrow,
                }
            })
        });
        Ok(())
    }

    pub fn get_state(
        &self,
        identifier: &IdentifierPrefix,
    ) -> Result<Option<IdentifierState>, Error> {
        self.validator.compute_state(identifier)
    }

    /// Get KERL for Prefix
    ///
    /// Returns the current validated KEL for a given Prefix
    pub fn get_kerl(&self, id: &IdentifierPrefix) -> Result<Option<Vec<u8>>, Error> {
        match self.db.get_kel_finalized_events(id) {
            Some(events) => Ok(Some(
                events
                    .map(|event| event.signed_event_message.serialize().unwrap_or_default())
                    .fold(vec![], |mut accum, serialized_event| {
                        accum.extend(serialized_event);
                        accum
                    }),
            )),
            None => Ok(None),
        }
    }

    pub fn get_event_at_sn(
        &self,
        id: &IdentifierPrefix,
        sn: u64,
    ) -> Result<Option<TimestampedSignedEventMessage>, Error> {
        self.validator.get_event_at_sn(id, sn)
    }

    /// Get last establishment event seal for Prefix
    ///
    /// Returns the EventSeal of last establishment event
    /// from KEL of given Prefix.
    pub fn get_last_establishment_event_seal(
        &self,
        id: &IdentifierPrefix,
    ) -> Result<Option<EventSeal>, Error> {
        let mut state = IdentifierState::default();
        let mut last_est = None;
        if let Some(events) = self.db.get_kel_finalized_events(id) {
            for event in events {
                state = state.apply(&event.signed_event_message.event_message.event)?;
                // TODO: is this event.event.event stuff too ugly? =)
                last_est = match event
                    .signed_event_message
                    .event_message
                    .event
                    .get_event_data()
                {
                    EventData::Icp(_) => Some(event.signed_event_message),
                    EventData::Rot(_) => Some(event.signed_event_message),
                    _ => last_est,
                }
            }
        } else {
            return Ok(None);
        }
        let seal = last_est.map(|event| EventSeal {
            prefix: event.event_message.event.get_prefix(),
            sn: event.event_message.event.get_sn(),
            event_digest: event.event_message.get_digest(),
        });
        Ok(seal)
    }

    /// Compute State for Prefix and sn
    ///
    /// Returns the State associated with the given
    /// Prefix after applying event of given sn.
    pub fn compute_state_at_sn(
        &self,
        id: &IdentifierPrefix,
        sn: u64,
    ) -> Result<Option<IdentifierState>, Error> {
        let mut state = IdentifierState::default();
        if let Some(events) = self.db.get_kel_finalized_events(id) {
            // TODO: testing approach if events come out sorted already (as they should coz of put sequence)
            let mut sorted_events = events.collect::<Vec<TimestampedSignedEventMessage>>();
            sorted_events.sort();
            for event in sorted_events
                .iter()
                .filter(|e| e.signed_event_message.event_message.event.get_sn() <= sn)
            {
                state = state.apply(&event.signed_event_message.event_message)?;
            }
        } else {
            return Ok(None);
        }
        Ok(Some(state))
    }

    pub fn has_receipt(
        &self,
        id: &IdentifierPrefix,
        sn: u64,
        validator_pref: &IdentifierPrefix,
    ) -> Result<bool, Error> {
        Ok(if let Some(receipts) = self.db.get_receipts_t(id) {
            receipts
                .filter(|r| r.body.event.sn.eq(&sn))
                .any(|receipt| receipt.validator_seal.prefix.eq(validator_pref))
        } else {
            false
        })
    }


    /// TODO Isn't it the same as `apply_to_state` function in validator?
    /// it won't process inception event successfully
    pub fn process_actual_event(
        &self,
        id: &IdentifierPrefix,
        event: impl EventSemantics,
    ) -> Result<Option<IdentifierState>, Error> {
        if let Some(state) = self.validator.compute_state(id)? {
            Ok(Some(event.apply_to(state)?))
        } else {
            Ok(None)
        }
    }
}
