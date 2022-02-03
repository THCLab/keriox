use std::sync::Arc;

use crate::{
    database::sled::SledEventDatabase,
    error::Error,
    event::{event_data::EventData, sections::seal::EventSeal},
    event_message::signed_event_message::TimestampedSignedEventMessage,
    prefix::IdentifierPrefix,
    state::{EventSemantics, IdentifierState},
};

use super::compute_state;

pub struct EventStorage {
    pub db: Arc<SledEventDatabase>,
}

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
    /// Returns the current validated KEL for a given Prefix
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
    /// it won't process inception event
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
