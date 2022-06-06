use std::sync::Arc;

use crate::{
    database::sled::SledEventDatabase,
    error::Error,
    event::{
        event_data::EventData,
        sections::{seal::EventSeal, KeyConfig},
    },
    event_message::{
        signed_event_message::{
            Message, SignedNontransferableReceipt, TimestampedSignedEventMessage,
        },
        Digestible,
    },
    event_parsing::SignedEventData,
    prefix::{BasicPrefix, IdentifierPrefix, SelfAddressingPrefix},
    state::{EventSemantics, IdentifierState},
};

#[cfg(feature = "query")]
use crate::query::{query_event::QueryArgsMbx, reply_event::SignedReply};

use super::compute_state;

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

    pub fn get_kel_messages_with_receipts(
        &self,
        id: &IdentifierPrefix,
    ) -> Result<Option<Vec<Message>>, Error> {
        match self.db.get_kel_finalized_events(id) {
            Some(events) => {
                let e = events
                    .map(|event| {
                        let rcts_from_db = self
                            .get_nt_receipts(
                                &event.signed_event_message.event_message.event.get_prefix(),
                                event.signed_event_message.event_message.event.get_sn(),
                                &event.signed_event_message.event_message.event.get_digest(),
                            )
                            .unwrap()
                            .map(Message::NontransferableRct);
                        match rcts_from_db {
                            Some(rct) => vec![Message::Event(event.into()), rct],
                            None => vec![Message::Event(event.into())],
                        }
                    })
                    .flatten()
                    .collect();
                Ok(Some(e))
            }
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

    #[cfg(feature = "query")]
    pub fn add_mailbox_receipt(&self, receipt: SignedNontransferableReceipt) -> Result<(), Error> {
        let id = receipt.body.event.prefix.clone();
        self.db.add_mailbox_receipt(receipt, &id)?;

        Ok(())
    }

    #[cfg(feature = "query")]
    pub fn get_mailbox_events(&self, args: QueryArgsMbx) -> Result<Vec<Message>, Error> {
        let id = args.pre.clone();

        let mut messages = Vec::new();

        // query receipts
        messages.extend(
            self.db
                .get_mailbox_receipts(&id)
                .into_iter()
                .flatten()
                .filter(|rec| rec.body.event.sn >= args.topics.receipt)
                .map(|rec| Message::NontransferableRct(rec)),
        );

        // TODO: query and return the rest of topics
        Ok(messages)
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

    pub fn get_nt_receipts(
        &self,
        prefix: &IdentifierPrefix,
        sn: u64,
        digest: &SelfAddressingPrefix,
    ) -> Result<Option<SignedNontransferableReceipt>, Error> {
        match self.db.get_receipts_nt(prefix) {
            Some(events) => Ok(events
                .filter(|rcp| rcp.body.event.sn == sn && &rcp.body.get_digest() == digest)
                .reduce(|acc, rct| {
                    let new_signatures = match (acc.couplets, rct.couplets) {
                        (None, None) => None,
                        (None, Some(new_couplets)) => Some(new_couplets),
                        (Some(couplets), None) => Some(couplets),
                        (Some(mut couplets), Some(mut new_coups)) => {
                            couplets.append(&mut new_coups);
                            Some(couplets)
                        }
                    };
                    SignedNontransferableReceipt {
                        couplets: new_signatures,
                        ..acc
                    }
                })),
            None => Ok(None),
        }
    }

    pub fn get_escrowed_nt_receipts(
        &self,
        prefix: &IdentifierPrefix,
    ) -> Result<Option<Vec<u8>>, Error> {
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

    pub fn get_nt_receipts_for_sn(
        &self,
        prefix: &IdentifierPrefix,
        sn: u64,
    ) -> Option<Vec<SignedNontransferableReceipt>> {
        self.db
            .get_escrow_nt_receipts(prefix)
            .map(|rcts| rcts.filter(|rct| rct.body.event.sn == sn).collect())
    }

    #[cfg(feature = "query")]
    pub fn get_last_ksn_reply(
        &self,
        creator_prefix: &IdentifierPrefix,
        signer_prefix: &IdentifierPrefix,
    ) -> Option<SignedReply> {
        use crate::query::reply_event::ReplyRoute;

        self.db
            .get_accepted_replys(creator_prefix)
            .and_then(|mut o| {
                o.find(|r: &SignedReply| {
                    if let ReplyRoute::Ksn(signer, _ksn) = r.reply.get_route() {
                        &signer == signer_prefix
                    } else {
                        false
                    }
                })
            })
    }

    fn compute_escrowed_state_at_event(
        &self,
        sn: u64,
        id: &IdentifierPrefix,
        event_digest: &SelfAddressingPrefix,
    ) -> Result<IdentifierState, Error> {
        // if receipted event is newer than current state, try to find receipted
        // event in partially witnessed escrow and apply it to state. Then we
        // can get current witness set.
        let escrowed_partially_witnessed = self
            .db
            .get_all_partially_witnessed()
            .and_then(|mut events| {
                events.find(|event| {
                    event.signed_event_message.event_message.event.content.sn == sn
                        && &event
                            .signed_event_message
                            .event_message
                            .event
                            .content
                            .prefix
                            == id
                        && &event.signed_event_message.event_message.get_digest() == event_digest
                })
            })
            .ok_or_else(|| Error::SemanticError("No escrowed event found".into()))?;
        let new_state = self
            .get_state(id)?
            .unwrap_or_default()
            .apply(&escrowed_partially_witnessed.signed_event_message)?;
        Ok(new_state)
    }

    /// Get current witness list for event
    ///
    /// Return current witnesses list for event identifier prefix, sn and
    /// digest. Also if event is escrowed as not fully witnessed.
    pub fn get_witnesses_at_event(
        &self,
        sn: u64,
        id: &IdentifierPrefix,
        event_digest: &SelfAddressingPrefix,
    ) -> Result<Vec<BasicPrefix>, Error> {
        let state = match self.get_state(id)? {
            Some(state) if state.sn < sn => {
                self.compute_escrowed_state_at_event(sn, id, event_digest)?
            }
            None => self.compute_escrowed_state_at_event(sn, id, event_digest)?,
            Some(state) => state,
        };
        Ok(state.witness_config.witnesses)
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
