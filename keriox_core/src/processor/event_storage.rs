use std::sync::Arc;

use super::compute_state;
use crate::sai::SelfAddressingPrefix;
use crate::{
    database::{timestamped::TimestampedSignedEventMessage, SledEventDatabase},
    error::Error,
    event::{
        event_data::EventData,
        sections::{seal::EventSeal, KeyConfig},
    },
    event_message::{
        signed_event_message::Notice, signed_event_message::SignedNontransferableReceipt,
        Digestible,
    },
    prefix::{BasicPrefix, IdentifierPrefix},
    state::{EventSemantics, IdentifierState},
};
#[cfg(feature = "query")]
use version::serialization_info::SerializationFormats;
#[cfg(feature = "query")]
use crate::{
    query::{
        key_state_notice::KeyStateNotice, query_event::QueryArgsMbx, reply_event::SignedReply,
    },
};

#[cfg(feature = "mailbox")]
use crate::{event_message::signed_event_message::SignedEventMessage, mailbox::MailboxResponse};

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
    pub fn get_kel_messages(&self, id: &IdentifierPrefix) -> Result<Option<Vec<Notice>>, Error> {
        match self.db.get_kel_finalized_events(id) {
            Some(events) => Ok(Some(
                events
                    .map(|event| Notice::Event(event.signed_event_message))
                    .collect(),
            )),
            None => Ok(None),
        }
    }

    pub fn get_kel_messages_with_receipts(
        &self,
        id: &IdentifierPrefix,
    ) -> Result<Option<Vec<Notice>>, Error> {
        match self.db.get_kel_finalized_events(id) {
            Some(events) => {
                let e = events
                    .map(|event| {
                        let rcts_from_db = self
                            .get_nt_receipts(
                                &event.signed_event_message.event_message.data.get_prefix(),
                                event.signed_event_message.event_message.data.get_sn(),
                                &event.signed_event_message.event_message.get_digest(),
                            )
                            .unwrap()
                            .map(Notice::NontransferableRct);
                        match rcts_from_db {
                            Some(rct) => vec![Notice::Event(event.into()), rct],
                            None => vec![Notice::Event(event.into())],
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
            Ok(events.find(|event| event.signed_event_message.event_message.data.get_sn() == sn))
        } else {
            Ok(None)
        }
    }

    #[cfg(feature = "mailbox")]
    pub fn add_mailbox_multisig(
        &self,
        receipient: &IdentifierPrefix,
        to_forward: SignedEventMessage,
    ) -> Result<(), Error> {
        self.db.add_mailbox_multisig(to_forward, receipient)?;

        Ok(())
    }

    #[cfg(feature = "mailbox")]
    pub fn add_mailbox_delegate(
        &self,
        receipient: &IdentifierPrefix,
        to_forward: SignedEventMessage,
    ) -> Result<(), Error> {
        self.db.add_mailbox_delegate(to_forward, receipient)?;

        Ok(())
    }

    #[cfg(feature = "mailbox")]
    pub fn add_mailbox_receipt(&self, receipt: SignedNontransferableReceipt) -> Result<(), Error> {
        let id = receipt.body.data.prefix.clone();
        self.db.add_mailbox_receipt(receipt, &id)?;

        Ok(())
    }

    #[cfg(feature = "mailbox")]
    pub fn add_mailbox_reply(&self, reply: SignedEventMessage) -> Result<(), Error> {
        let id = reply.event_message.data.get_prefix();
        self.db.add_mailbox_reply(reply, &id)?;

        Ok(())
    }

    #[cfg(feature = "mailbox")]
    pub fn get_mailbox_messages(&self, args: QueryArgsMbx) -> Result<MailboxResponse, Error> {
        let id = args.i.clone();

        // query receipts
        let receipt = self
            .db
            .get_mailbox_receipts(&id)
            .into_iter()
            .flatten()
            .filter(|rec| rec.body.data.sn >= args.topics.receipt)
            .collect();

        let multisig = self
            .db
            .get_mailbox_multisig(&id)
            .map(|it| {
                it.skip(args.topics.multisig)
                    .map(|ev| ev.signed_event_message)
                    .collect()
            })
            .unwrap_or_default();

        let delegate = match self.db.get_mailbox_delegate(&id) {
            Some(msgs) => msgs.map(|e| e.signed_event_message).collect(),
            None => vec![],
        };

        let mut messages = vec![];
        // query replies
        messages.extend(
            self.db
                .get_mailbox_replies(&id)
                .into_iter()
                .flatten()
                .filter(|rpy| rpy.event_message.data.get_sn() >= args.topics.reply)
                .map(|rpy| Notice::Event(rpy)),
        );

        // TODO: query and return the rest of topics
        Ok(MailboxResponse {
            receipt,
            multisig,
            delegate,
        })
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
                state = state.apply(&event.signed_event_message.event_message.data)?;
                // TODO: is this event.event.event stuff too ugly? =)
                last_est = match event
                    .signed_event_message
                    .event_message
                    .data
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
            prefix: event.event_message.data.get_prefix(),
            sn: event.event_message.data.get_sn(),
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
                .filter(|e| e.signed_event_message.event_message.data.get_sn() <= sn)
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
                .compare_digest(event_digest)?
            {
                // return the config or error if it's not an establishment event
                Ok(Some(
                    match event
                        .signed_event_message
                        .event_message
                        .data
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
                .filter(|r| r.body.data.sn.eq(&sn))
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
                .filter(|rcp| rcp.body.data.sn == sn && &rcp.body.get_digest() == digest)
                .reduce(|acc, rct| {
                    let mut new_signatures = acc.signatures;
                    new_signatures.append(&mut rct.signatures.clone());
                    SignedNontransferableReceipt {
                        signatures: new_signatures,
                        ..acc
                    }
                })),
            None => Ok(None),
        }
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

    /// Compute state at event given by sn and digest.
    ///
    /// Return current state for event identifier prefix, sn and
    /// digest.
    pub fn compute_state_at_event(
        &self,
        sn: u64,
        id: &IdentifierPrefix,
        event_digest: &SelfAddressingPrefix,
    ) -> Result<Option<IdentifierState>, Error> {
        let new_state = self.compute_state_at_sn(id, sn)?;
        if let Some(ref state) = new_state {
            if &state.last_event_digest == event_digest {
                Ok(new_state)
            } else {
                Err(Error::SemanticError(
                    "Event digest doesn't match last event digest".into(),
                ))
            }
        } else {
            Ok(None)
        }
    }

    /// Get current witness list for event
    ///
    /// Return current witnesses list for event identifier prefix, sn and
    /// digest.
    pub fn get_witnesses_at_event(
        &self,
        sn: u64,
        id: &IdentifierPrefix,
        event_digest: &SelfAddressingPrefix,
    ) -> Result<Vec<BasicPrefix>, Error> {
        let state = self
            .compute_state_at_event(sn, id, event_digest)?
            .ok_or(Error::MissingEvent)?;
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

    #[cfg(feature = "query")]
    pub fn get_ksn_for_prefix(
        &self,
        prefix: &IdentifierPrefix,
        format: SerializationFormats,
    ) -> Result<KeyStateNotice, Error> {

        let state = self
            .get_state(prefix)?
            .ok_or_else(|| Error::SemanticError("No state in db".into()))?;
        Ok(KeyStateNotice::new_ksn(state, format))
    }
}
