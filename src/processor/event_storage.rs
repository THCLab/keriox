use std::sync::Arc;

use crate::{
    database::sled::SledEventDatabase,
    error::Error,
    event::{
        event_data::EventData,
        sections::{seal::EventSeal, KeyConfig},
    },
    event_message::signed_event_message::{
        Message, SignedNontransferableReceipt, TimestampedSignedEventMessage,
    },
    event_parsing::SignedEventData,
    prefix::{
        AttachedSignaturePrefix, BasicPrefix, IdentifierPrefix, SelfAddressingPrefix,
        SelfSigningPrefix,
    },
    state::{EventSemantics, IdentifierState},
};

use super::compute_state;
#[cfg(feature = "query")]
use crate::query::reply::SignedReply;

pub struct EventStorage {
    pub db: Arc<SledEventDatabase>,
}

// Collection of methods for getting data from database.
impl EventStorage {
    pub fn new(db: Arc<SledEventDatabase>) -> Self {
        Self { db }
    }

    pub fn get_state(
        &self,
        identifier: &IdentifierPrefix,
    ) -> Result<Option<IdentifierState>, Error> {
        compute_state(self.db.clone(), identifier)
    }

    /// Get KERL for Prefix
    ///
    /// Returns serialized current validated KEL for a given Prefix
    pub fn get_kel(&self, id: &IdentifierPrefix) -> Result<Option<Vec<u8>>, Error> {
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

    /// Get KERL for Prefix
    ///
    /// Returns the current validated KEL for a given Prefix
    pub fn get_kel_messages(&self, id: &IdentifierPrefix) -> Result<Option<Vec<Message>>, Error> {
        match self.db.get_kel_finalized_events(id) {
            Some(events) => Ok(Some(
                events
                    .map(|event| Message::Event(event.signed_event_message))
                    .collect(),
            )),
            None => Ok(None),
        }
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

    /// Get keys from Establishment Event
    ///
    /// Returns the current Key Config associated with
    /// the given Prefix at the establishment event
    /// represented by sn and Event Digest
    pub fn get_keys_at_event(
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
                        _ => return Err(Error::SemanticError("Not an establishment event".into())),
                    },
                ))
            } else {
                Err(Error::SemanticError("Event digests doesn't match".into()))
            }
        } else {
            Err(Error::EventOutOfOrderError)
        }
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

    pub fn get_nt_receipts(&self, prefix: &IdentifierPrefix) -> Result<Option<Vec<u8>>, Error> {
        match self.db.get_escrow_nt_receipts(prefix) {
            Some(events) => Ok(Some(
                events
                    .map(|event| SignedEventData::from(event).to_cesr().unwrap_or_default())
                    .fold(vec![], |mut accum, serialized_event| {
                        accum.extend(serialized_event);
                        accum
                    }),
            )),
            None => Ok(None),
        }
    }

    pub fn get_receipt_couplets(
        &self,
        rct: &SignedNontransferableReceipt,
    ) -> Result<Vec<(BasicPrefix, SelfSigningPrefix)>, Error> {
        let get_witness_couplets = |storage: &EventStorage,
                                    receipt: &SignedNontransferableReceipt,
                                    indexed_signatures: &[AttachedSignaturePrefix]|
         -> Result<Vec<_>, Error> {
            let pref = receipt.body.event.prefix.clone();
            let witnesses = storage
                .get_state(&pref)?
                // if there is no state for id, receipt is out of order.
                .ok_or(Error::EventOutOfOrderError)?
                .witness_config
                .witnesses;
            indexed_signatures
                .iter()
                .map(|sig| -> Result<_, _> {
                    Ok((
                        witnesses
                            .get(sig.index as usize)
                            .ok_or_else(|| {
                                Error::SemanticError("No witness of given index".into())
                            })?
                            .clone(),
                        sig.signature.clone(),
                    ))
                })
                .collect::<Result<Vec<_>, _>>()
        };
        match (&rct.couplets, &rct.indexed_sigs) {
            (None, None) => Ok(vec![]),
            (None, Some(indexed_sigs)) => get_witness_couplets(self, rct, indexed_sigs),
            (Some(coups), None) => Ok(coups.clone()),
            (Some(coups), Some(indexed_sigs)) => {
                let mut out = get_witness_couplets(self, rct, indexed_sigs)?;
                out.append(&mut coups.clone());
                Ok(out)
            }
        }
    }

    pub fn get_nt_receipts_signatures(
        &self,
        prefix: &IdentifierPrefix,
        sn: u64,
    ) -> Option<Vec<(BasicPrefix, SelfSigningPrefix)>> {
        self.db.get_escrow_nt_receipts(prefix).map(|rcts| {
            let (oks, _errs): (Vec<_>, Vec<_>) = rcts
                .filter(|rct| rct.body.event.sn == sn)
                .map(|rct| -> Result<Vec<(_, _)>, _> { self.get_receipt_couplets(&rct) })
                .partition(Result::is_ok);
            oks.into_iter().flat_map(|e| e.unwrap()).collect()
        })
    }

    #[cfg(feature = "query")]
    pub fn get_last_reply(
        &self,
        creator_prefix: &IdentifierPrefix,
        signer_prefix: &IdentifierPrefix,
    ) -> Option<SignedReply> {
        use crate::query::Route;

        self.db
            .get_accepted_replys(creator_prefix)
            .and_then(|mut o| {
                o.find(|r: &SignedReply| {
                    r.reply.event.get_route() == Route::ReplyKsn(signer_prefix.to_owned())
                })
            })
    }

    /// TODO Isn't it the same as `apply_to_state` function in validator?
    /// it won't process inception event because compute_state returns None
    /// in that case
    pub fn process_actual_event(
        &self,
        id: &IdentifierPrefix,
        event: impl EventSemantics,
    ) -> Result<Option<IdentifierState>, Error> {
        if let Some(state) = compute_state(self.db.clone(), id)? {
            Ok(Some(event.apply_to(state)?))
        } else {
            Ok(None)
        }
    }
}
