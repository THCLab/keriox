#[cfg(feature = "query")]
use crate::query::{key_state_notice::KeyStateNotice, reply::SignedReply, QueryError};
#[cfg(feature = "query")]
use chrono::{DateTime, FixedOffset};
use std::sync::Arc;

use crate::{
    database::sled::SledEventDatabase,
    error::Error,
    event::{
        event_data::EventData,
        sections::{
            seal::{EventSeal, Seal},
            KeyConfig,
        },
        EventMessage,
    },
    event_message::{
        key_event_message::KeyEvent,
        signature::Signature,
        signed_event_message::{
            Message, SignedEventMessage, SignedNontransferableReceipt, SignedTransferableReceipt,
            TimestampedSignedEventMessage,
        },
    },
    prefix::{IdentifierPrefix, SelfAddressingPrefix},
    state::{EventSemantics, IdentifierState},
};

#[cfg(feature = "async")]
pub mod async_processing;
#[cfg(test)]
mod tests;

pub struct EventProcessor {
    pub db: Arc<SledEventDatabase>,
}

impl EventProcessor {
    pub fn new(db: Arc<SledEventDatabase>) -> Self {
        Self { db }
    }

    /// Compute State for Prefix
    ///
    /// Returns the current State associated with
    /// the given Prefix
    pub fn compute_state(&self, id: &IdentifierPrefix) -> Result<Option<IdentifierState>, Error> {
        // start with empty state
        let mut state = IdentifierState::default();
        if let Some(events) = self.db.get_kel_finalized_events(id) {
            // we sort here to get inception first
            let mut sorted_events = events.collect::<Vec<TimestampedSignedEventMessage>>();
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
        } else {
            // no inception event, no state
            return Ok(None);
        }
        Ok(Some(state))
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

    /// Get keys from Establishment Event
    ///
    /// Returns the current Key Config associated with
    /// the given Prefix at the establishment event
    /// represented by sn and Event Digest
    fn get_keys_at_event(
        &self,
        id: &IdentifierPrefix,
        sn: u64,
        event_digest: &SelfAddressingPrefix,
    ) -> Result<Option<KeyConfig>, Error> {
        if let Ok(Some(event)) = self.get_event_at_sn(id, sn) {
            // if it's the event we're looking for
            if event
                .signed_event_message
                .event_message
                .check_digest(event_digest)?
            {
                // return the config or error if it's not an establishment event
                Ok(Some(
                    match event
                        .signed_event_message
                        .event_message
                        .event
                        .get_event_data()
                    {
                        EventData::Icp(icp) => icp.key_config,
                        EventData::Rot(rot) => rot.key_config,
                        EventData::Dip(dip) => dip.inception_data.key_config,
                        EventData::Drt(drt) => drt.key_config,
                        // the receipt has a binding but it's NOT an establishment event
                        _ => return Err(Error::SemanticError("Receipt binding incorrect".into())),
                    },
                ))
            } else {
                Err(Error::SemanticError("Event digests doesn't match".into()))
            }
        } else {
            Err(Error::EventOutOfOrderError)
        }
    }

    /// Validate delegating event seal.
    ///
    /// Validates binding between delegated and delegating events. The validation
    /// is based on delegating event seal and delegated event.
    fn validate_seal(
        &self,
        seal: EventSeal,
        delegated_event: &EventMessage<KeyEvent>,
    ) -> Result<(), Error> {
        // Check if event of seal's prefix and sn is in db.
        if let Ok(Some(event)) = self.get_event_at_sn(&seal.prefix, seal.sn) {
            // Extract prior_digest and data field from delegating event.
            let data = match event
                .signed_event_message
                .event_message
                .event
                .get_event_data()
            {
                EventData::Rot(rot) => rot.data,
                EventData::Ixn(ixn) => ixn.data,
                EventData::Drt(drt) => drt.data,
                _ => return Err(Error::SemanticError("Improper event type".to_string())),
            };

            // Check if event seal list contains delegating event seal.
            if !data.iter().any(|s| match s {
                Seal::Event(es) => delegated_event.check_digest(&es.event_digest).unwrap(),
                _ => false,
            }) {
                return Err(Error::SemanticError(
                    "Data field doesn't contain delegating event seal.".to_string(),
                ));
            };
        } else {
            return Err(Error::EventOutOfOrderError);
        }
        Ok(())
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

    /// Process
    ///
    /// Process a deserialized KERI message
    pub fn process(&self, data: Message) -> Result<Option<IdentifierState>, Error> {
        match data {
            Message::Event(e) => self.process_event(&e),
            Message::NontransferableRct(rct) => self.process_witness_receipt(rct),
            Message::TransferableRct(rct) => self.process_validator_receipt(rct),
            #[cfg(feature = "query")]
            Message::KeyStateNotice(ksn_rpy) => self.process_signed_reply(&ksn_rpy),
            #[cfg(feature = "query")]
            Message::Query(_qry) => todo!(),
        }
    }

    pub fn process_actual_event(
        &self,
        id: &IdentifierPrefix,
        event: impl EventSemantics,
    ) -> Result<Option<IdentifierState>, Error> {
        if let Some(state) = self.compute_state(id)? {
            Ok(Some(event.apply_to(state)?))
        } else {
            Ok(None)
        }
    }

    /// Process Event
    ///
    /// Validates a Key Event against the latest state
    /// of the Identifier and applies it to update the state
    /// returns the updated state
    /// TODO improve checking and handling of errors!
    pub fn process_event(
        &self,
        signed_event: &SignedEventMessage,
    ) -> Result<Option<IdentifierState>, Error> {
        // Log event.

        let id = &signed_event.event_message.event.get_prefix();

        // If delegated event, check its delegator seal.
        match signed_event.event_message.event.get_event_data() {
            EventData::Dip(dip) => {
                let (sn, dig) = signed_event
                    .delegator_seal
                    .as_ref()
                    .map(|seal| (seal.sn, seal.digest.clone()))
                    .ok_or_else(|| Error::SemanticError("Missing source seal".into()))?;
                let seal = EventSeal {
                    prefix: dip.delegator,
                    sn,
                    event_digest: dig,
                };
                self.validate_seal(seal, &signed_event.event_message)
            }
            EventData::Drt(_drt) => {
                let delegator = self
                    .compute_state(&signed_event.event_message.event.get_prefix())?
                    .ok_or_else(|| {
                        Error::SemanticError("Missing state of delegated identifier".into())
                    })?
                    .delegator
                    .ok_or_else(|| Error::SemanticError("Missing delegator".into()))?;
                let (sn, dig) = signed_event
                    .delegator_seal
                    .as_ref()
                    .map(|seal| (seal.sn, seal.digest.clone()))
                    .ok_or_else(|| Error::SemanticError("Missing source seal".into()))?;
                let seal = EventSeal {
                    prefix: delegator,
                    sn,
                    event_digest: dig,
                };
                self.validate_seal(seal, &signed_event.event_message)
            }
            _ => Ok(()),
        }?;
        self.apply_to_state(&signed_event.event_message)
            .and_then(|new_state| {
                // add event from the get go and clean it up on failure later
                self.db.add_kel_finalized_event(signed_event.clone(), id)?;
                // match on verification result
                match new_state
                    .current
                    .verify(
                        &signed_event.event_message.serialize()?,
                        &signed_event.signatures,
                    )
                    .and_then(|result| {
                        if !result {
                            Err(Error::SignatureVerificationError)
                        } else {
                            // TODO should check if there are enough receipts and probably escrow
                            Ok(new_state)
                        }
                    }) {
                    Ok(state) => Ok(Some(state)),
                    Err(e) => {
                        if let Error::EventDuplicateError = e {
                            self.db.add_duplicious_event(signed_event.clone(), id)?
                        };
                        // remove last added event
                        self.db.remove_kel_finalized_event(id, signed_event)?;
                        Err(e)
                    }
                }
            })
    }

    /// Process Validator Receipt
    ///
    /// Checks the receipt against the receipted event
    /// and the state of the validator, returns the state
    /// of the identifier being receipted
    /// TODO improve checking and handling of errors!
    pub fn process_validator_receipt(
        &self,
        vrc: SignedTransferableReceipt,
    ) -> Result<Option<IdentifierState>, Error> {
        if let Ok(Some(event)) = self.get_event_at_sn(&vrc.body.event.prefix, vrc.body.event.sn) {
            let kp = self.get_keys_at_event(
                &vrc.validator_seal.prefix,
                vrc.validator_seal.sn,
                &vrc.validator_seal.event_digest,
            )?;
            if kp.is_some()
                && kp.unwrap().verify(
                    &event.signed_event_message.event_message.serialize()?,
                    &vrc.signatures,
                )?
            {
                self.db.add_receipt_t(vrc.clone(), &vrc.body.event.prefix)
            } else {
                Err(Error::SemanticError("Incorrect receipt signatures".into()))
            }
        } else {
            self.db
                .add_escrow_t_receipt(vrc.clone(), &vrc.body.event.prefix)?;
            Err(Error::SemanticError("Receipt escrowed".into()))
        }?;
        self.compute_state(&vrc.body.event.prefix)
    }

    /// Process Witness Receipt
    ///
    /// Checks the receipt against the receipted event
    /// returns the state of the Identifier being receipted,
    /// which may have been updated by un-escrowing events
    /// TODO improve checking and handling of errors!
    pub fn process_witness_receipt(
        &self,
        rct: SignedNontransferableReceipt,
    ) -> Result<Option<IdentifierState>, Error> {
        // get event which is being receipted
        let id = &rct.body.event.prefix.to_owned();
        if let Ok(Some(event)) = self.get_event_at_sn(&rct.body.event.prefix, rct.body.event.sn) {
            let serialized_event = event.signed_event_message.serialize()?;
            let (_, mut errors): (Vec<_>, Vec<Result<bool, Error>>) = rct
                .clone()
                .couplets
                .into_iter()
                .map(|(witness, receipt)| witness.verify(&serialized_event, &receipt))
                .partition(Result::is_ok);
            if errors.is_empty() {
                self.db.add_receipt_nt(rct, id)?
            } else {
                let e = errors.pop().unwrap().unwrap_err();
                return Err(e);
            }
        } else {
            self.db.add_escrow_nt_receipt(rct, id)?
        }
        self.compute_state(id)
    }

    pub fn get_event_at_sn(
        &self,
        id: &IdentifierPrefix,
        sn: u64,
    ) -> Result<Option<TimestampedSignedEventMessage>, Error> {
        if let Some(mut events) = self.db.get_kel_finalized_events(id) {
            Ok(events.find(|event| event.signed_event_message.event_message.event.get_sn() == sn))
        } else {
            Ok(None)
        }
    }

    fn apply_to_state(&self, event: &EventMessage<KeyEvent>) -> Result<IdentifierState, Error> {
        // get state for id (TODO cache?)
        self.compute_state(&event.event.get_prefix())
            // get empty state if there is no state yet
            .map(|opt| opt.map_or_else(IdentifierState::default, |s| s))
            // process the event update
            .and_then(|state| event.apply_to(state))
    }

    pub fn verify(&self, data: &[u8], sig: &Signature) -> Result<(), Error> {
        match sig {
            Signature::Transferable(seal, sigs) => {
                let kp = self.get_keys_at_event(&seal.prefix, seal.sn, &seal.event_digest)?;
                (kp.is_some() && kp.unwrap().verify(data, sigs)?)
                    .then(|| ())
                    .ok_or(Error::SignatureVerificationError)
            }
            Signature::NonTransferable(bp, sign) => bp
                .verify(data, sign)?
                .then(|| ())
                .ok_or(Error::SignatureVerificationError),
        }
    }

    #[cfg(feature = "query")]
    fn bada_logic(&self, new_rpy: &SignedReply) -> Result<(), Error> {
        use crate::query::{reply::ReplyEvent, Route};
        let accepted_replys = self
            .db
            .get_accepted_replys(&new_rpy.reply.event.get_prefix());

        // helper function for reply timestamps checking
        fn check_dts(new_rpy: &ReplyEvent, old_rpy: &ReplyEvent) -> Result<(), Error> {
            let new_dt = new_rpy.get_timestamp();
            let old_dt = old_rpy.get_timestamp();
            if new_dt >= old_dt {
                Ok(())
            } else {
                Err(QueryError::StaleRpy.into())
            }
        }
        match new_rpy.signature.clone() {
            Signature::Transferable(seal, _sigs) => {
                // A) If sn (sequence number) of last (if forked) Est evt that provides
                //  keys for signature(s) of new is greater than sn of last Est evt
                //  that provides keys for signature(s) of old.

                //  Or

                //  B) If sn of new equals sn of old And date-time-stamp of new is
                //     greater than old

                // get last reply for prefix with route with sender_prefix
                match accepted_replys.and_then(|mut o| {
                    o.find(|r: &SignedReply| {
                        r.reply.event.get_route() == Route::ReplyKsn(seal.prefix.clone())
                    })
                }) {
                    Some(old_rpy) => {
                        // check sns
                        let new_sn = seal.sn.clone();
                        let old_sn: u64 =
                            if let Signature::Transferable(seal, _) = old_rpy.signature {
                                seal.sn
                            } else {
                                return Err(QueryError::Error(
                                    "Improper signature type. Should be transferable.".into(),
                                )
                                .into());
                            };
                        if old_sn < new_sn {
                            Ok(())
                        } else if old_sn == new_sn {
                            check_dts(&new_rpy.reply.event, &old_rpy.reply.event)
                        } else {
                            Err(QueryError::StaleRpy.into())
                        }
                    }
                    None => Err(QueryError::NoSavedReply.into()),
                }
            }
            Signature::NonTransferable(bp, _sig) => {
                //  If date-time-stamp of new is greater than old
                match accepted_replys.and_then(|mut o| {
                    o.find(|r| {
                        r.reply.event.get_route()
                            == Route::ReplyKsn(IdentifierPrefix::Basic(bp.clone()))
                    })
                }) {
                    Some(old_rpy) => check_dts(&new_rpy.reply.event, &old_rpy.reply.event),
                    None => Err(QueryError::NoSavedReply.into()),
                }
            }
        }
    }

    #[cfg(feature = "query")]
    pub fn process_signed_reply(
        &self,
        rpy: &SignedReply,
    ) -> Result<Option<IdentifierState>, Error> {
        use crate::query::Route;

        let route = rpy.reply.event.get_route();
        // check if signature was made by ksn creator
        if let Route::ReplyKsn(ref aid) = route {
            if &rpy.signature.get_signer() != aid {
                return Err(QueryError::Error("Wrong reply message signer".into()).into());
            };
            let verification_result = self.verify(&rpy.reply.serialize()?, &rpy.signature);
            if let Err(Error::EventOutOfOrderError) = verification_result {
                self.escrow_reply(&rpy)?;
                return Err(Error::QueryError(QueryError::OutOfOrderEventError));
            }
            verification_result?;
            rpy.reply.check_digest()?;
            let bada_result = self.bada_logic(&rpy);
            match bada_result {
                Err(Error::QueryError(QueryError::NoSavedReply)) => {
                    // no previous rpy event to compare
                    Ok(())
                }
                anything => anything,
            }?;
            // now unpack ksn and check its details
            let ksn = rpy.reply.event.get_reply_data();
            let ksn_checking_result = self.check_ksn(&ksn, aid);
            if let Err(Error::QueryError(QueryError::OutOfOrderEventError)) = ksn_checking_result {
                self.escrow_reply(&rpy)?;
            };
            ksn_checking_result?;
            self.db
                .update_accepted_reply(rpy.clone(), &rpy.reply.event.get_prefix())?;
            Ok(Some(rpy.reply.event.get_state()))
        } else {
            Err(Error::SemanticError("wrong route type".into()))
        }
    }

    #[cfg(feature = "query")]
    pub fn check_timestamp_with_last_ksn(
        &self,
        new_dt: DateTime<FixedOffset>,
        pref: &IdentifierPrefix,
        aid: &IdentifierPrefix,
    ) -> Result<(), Error> {
        use crate::query::Route;

        match self
            .db
            .get_accepted_replys(pref)
            .ok_or(Error::QueryError(QueryError::OutOfOrderEventError))?
            .find(|sr: &SignedReply| sr.reply.event.get_route() == Route::ReplyKsn(aid.clone()))
        {
            Some(old_ksn) => {
                let old_dt = old_ksn.reply.event.get_timestamp();
                if old_dt > new_dt {
                    Err(QueryError::StaleKsn.into())
                } else {
                    Ok(())
                }
            }
            None => {
                // TODO should be ok, if there's no old ksn in db?
                // Ok(())
                Err(QueryError::OutOfOrderEventError.into())
            }
        }
    }

    #[cfg(feature = "query")]
    fn check_ksn(
        &self,
        ksn: &KeyStateNotice,
        aid: &IdentifierPrefix,
    ) -> Result<Option<IdentifierState>, Error> {
        // check ksn digest
        let ksn_sn = ksn.state.sn;
        let ksn_pre = ksn.state.prefix.clone();
        let event_from_db = self
            .get_event_at_sn(&ksn_pre, ksn_sn)?
            .ok_or(Error::QueryError(QueryError::OutOfOrderEventError))?
            .signed_event_message
            .event_message;
        event_from_db
            .check_digest(&ksn.state.last_event_digest)?
            .then(|| ())
            .ok_or::<Error>(Error::IncorrectDigest)?;

        match self.check_timestamp_with_last_ksn(ksn.timestamp, &ksn_pre, aid) {
            Err(Error::QueryError(QueryError::OutOfOrderEventError)) => {
                // no previous accepted ksn from that aid in db
                Ok(())
            }
            e => e,
        }?;

        // check new ksn with actual database state for that prefix
        let state = self
            .compute_state(&ksn_pre)?
            .ok_or::<Error>(QueryError::OutOfOrderEventError.into())?;
        if state.sn < ksn_sn {
            Err(QueryError::OutOfOrderEventError.into())
        } else if state.sn == ksn_sn {
            Ok(Some(state))
        } else {
            Err(QueryError::StaleKsn.into())
        }
    }

    #[cfg(feature = "query")]
    fn escrow_reply(&self, rpy: &SignedReply) -> Result<(), Error> {
        let id = rpy.reply.event.get_prefix();
        self.db.add_escrowed_reply(rpy.clone(), &id)
    }

    #[cfg(feature = "query")]
    pub fn process_escrow(&self) -> Result<(), Error> {
        self.db.get_all_escrowed_replys().map(|esc| {
            esc.for_each(|sig_rep| {
                match self.process_signed_reply(&sig_rep) {
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
}
