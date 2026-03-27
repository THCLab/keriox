use std::sync::Arc;

use super::compute_state;
#[cfg(feature = "query")]
use crate::query::{key_state_notice::KeyStateNotice, reply_event::SignedReply};
use crate::{
    actor::prelude::Message,
    database::timestamped::{Timestamped, TimestampedSignedEventMessage},
    error::Error,
    event::{
        event_data::EventData,
        sections::{seal::EventSeal, KeyConfig},
    },
    event_message::{
        signature::Transferable,
        signed_event_message::{Notice, SignedNontransferableReceipt},
    },
    prefix::{BasicPrefix, IdentifierPrefix},
    state::{EventSemantics, IdentifierState},
};
#[cfg(feature = "mailbox")]
use crate::{
    database::mailbox::MailboxData,
    query::mailbox::QueryArgsMbx,
};
use crate::{
    database::{EventDatabase, QueryParameters},
    event_message::signed_event_message::SignedEventMessage,
};
#[cfg(feature = "query")]
use said::version::format::SerializationFormats;
use said::SelfAddressingIdentifier;

#[cfg(feature = "mailbox")]
use crate::mailbox::MailboxResponse;

pub struct EventStorage<D: EventDatabase> {
    pub events_db: Arc<D>,
    #[cfg(feature = "mailbox")]
    pub mailbox_data: Option<MailboxData>,
}

impl<D: EventDatabase> EventStorage<D> {
    pub fn new(events_db: Arc<D>) -> Self {
        Self {
            events_db,
            #[cfg(feature = "mailbox")]
            mailbox_data: None,
        }
    }
}

#[cfg(feature = "mailbox")]
impl EventStorage<crate::database::redb::RedbDatabase> {
    pub fn new_redb(events_db: Arc<crate::database::redb::RedbDatabase>) -> Self {
        let mailbox_data = MailboxData::new(events_db.db.clone()).unwrap();
        Self {
            events_db,
            mailbox_data: Some(mailbox_data),
        }
    }
}

#[cfg(feature = "mailbox")]
impl<D: EventDatabase> EventStorage<D> {
    pub fn new_with_mailbox(events_db: Arc<D>, mailbox_data: MailboxData) -> Self {
        Self {
            events_db,
            mailbox_data: Some(mailbox_data),
        }
    }
}

impl<D: EventDatabase> EventStorage<D> {
    pub fn get_state(&self, identifier: &IdentifierPrefix) -> Option<IdentifierState> {
        self.events_db.get_key_state(identifier)
    }

    /// Get KEL for Prefix
    ///
    /// Returns serialized in CESR current validated KEL for a given Prefix
    pub fn get_kel(&self, id: &IdentifierPrefix) -> Result<Option<Vec<u8>>, Error> {
        let kel = self.get_kel_messages(id)?;
        Ok(kel.map(|events| {
            events
                .into_iter()
                .map(|event| Message::Notice(event).to_cesr().unwrap_or_default())
                .fold(vec![], |mut accum, serialized_event| {
                    accum.extend(serialized_event);
                    accum
                })
        }))
    }

    /// Get KERL for Prefix
    ///
    /// Returns the current validated KEL for a given Prefix
    pub fn get_kel_messages(&self, id: &IdentifierPrefix) -> Result<Option<Vec<Notice>>, Error> {
        match self
            .events_db
            .get_kel_finalized_events(QueryParameters::All { id })
        {
            Some(events) => Ok(Some(
                events
                    .map(|event| Notice::Event(event.signed_event_message))
                    .collect(),
            )),
            None => Ok(None),
        }
    }

    pub fn get_kel_messages_with_receipts_all(
        &self,
        id: &IdentifierPrefix,
    ) -> Result<Option<Vec<Notice>>, Error> {
        let events = self
            .events_db
            .get_kel_finalized_events(QueryParameters::All { id })
            .map(|events| {
                events
                    .map(|e| Notice::Event(e.signed_event_message))
                    .collect()
            });
        Ok(events)
    }

    pub fn get_kel_messages_with_receipts_range(
        &self,
        id: &IdentifierPrefix,
        sn: u64,
        limit: u64,
    ) -> Result<Option<Vec<Notice>>, Error> {
        let events = self
            .events_db
            .get_kel_finalized_events(QueryParameters::Range {
                id: id.clone(),
                start: sn,
                limit,
            })
            .and_then(|events| self.collect_with_receipts(events));
        Ok(events)
    }

    fn collect_with_receipts<'a, I>(&self, events: I) -> Option<Vec<Notice>>
    where
        I: IntoIterator<Item = Timestamped<SignedEventMessage>>,
    {
        let evs: Vec<_> = events
            .into_iter()
            .flat_map(|event: Timestamped<SignedEventMessage>| {
                let rcts_from_db = self
                    .get_nt_receipts(
                        &event.signed_event_message.event_message.data.get_prefix(),
                        event.signed_event_message.event_message.data.get_sn(),
                    )
                    .unwrap()
                    .map(Notice::NontransferableRct);
                match rcts_from_db {
                    Some(rct) => vec![Notice::Event(event.signed_event_message), rct],
                    None => vec![Notice::Event(event.into())],
                }
            })
            .collect();
        if evs.is_empty() {
            None
        } else {
            Some(evs)
        }
    }

    pub fn get_event_at_sn(
        &self,
        id: &IdentifierPrefix,
        sn: u64,
    ) -> Option<TimestampedSignedEventMessage> {
        if let Some(mut events) = self
            .events_db
            .get_kel_finalized_events(QueryParameters::BySn { id: id.clone(), sn })
        {
            events.find(|event| event.signed_event_message.event_message.data.get_sn() == sn)
        } else {
            None
        }
    }

    #[cfg(feature = "mailbox")]
    fn mailbox(&self) -> Result<&MailboxData, Error> {
        self.mailbox_data
            .as_ref()
            .ok_or_else(|| Error::SemanticError("Mailbox not initialized".into()))
    }

    #[cfg(feature = "mailbox")]
    pub fn add_mailbox_multisig(
        &self,
        receipient: &IdentifierPrefix,
        to_forward: SignedEventMessage,
    ) -> Result<(), Error> {
        self.mailbox()?
            .add_mailbox_multisig(receipient, to_forward)?;

        Ok(())
    }

    #[cfg(feature = "mailbox")]
    pub fn add_mailbox_delegate(
        &self,
        receipient: &IdentifierPrefix,
        to_forward: SignedEventMessage,
    ) -> Result<(), Error> {
        self.mailbox()?
            .add_mailbox_delegate(receipient, to_forward)?;

        Ok(())
    }

    #[cfg(feature = "mailbox")]
    pub fn add_mailbox_receipt(&self, receipt: SignedNontransferableReceipt) -> Result<(), Error> {
        let id = receipt.body.prefix.clone();
        self.mailbox()?.add_mailbox_receipt(&id, receipt)?;

        Ok(())
    }

    #[cfg(feature = "mailbox")]
    pub fn add_mailbox_reply(&self, reply: SignedEventMessage) -> Result<(), Error> {
        let id = reply.event_message.data.get_prefix();
        self.mailbox()?.add_mailbox_reply(&id, reply)?;

        Ok(())
    }

    #[cfg(feature = "mailbox")]
    pub fn get_mailbox_messages(&self, args: &QueryArgsMbx) -> Result<MailboxResponse, Error> {
        let mailbox = self.mailbox()?;
        let id = args.i.clone();

        // query receipts
        let receipt = match mailbox
            .get_mailbox_receipts(&id, args.topics.receipt as u64)
        {
            Some(receipts) => receipts.collect(),
            None => vec![],
        };

        let multisig = match mailbox
            .get_mailbox_multisig(&id, args.topics.multisig as u64)
        {
            Some(multisig) => multisig.collect(),
            None => vec![],
        };

        let delegate = match mailbox
            .get_mailbox_delegate(&id, args.topics.delegate as u64)
        {
            Some(delegate) => delegate.collect(),
            None => vec![],
        };

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
    pub fn get_last_establishment_event_seal(&self, id: &IdentifierPrefix) -> Option<EventSeal> {
        let mut state = IdentifierState::default();
        let mut last_est = None;
        if let Some(events) = self
            .events_db
            .get_kel_finalized_events(QueryParameters::All { id })
        {
            for event in events {
                state = state
                    .apply(&event.signed_event_message.event_message.data)
                    .unwrap();
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
            return None;
        }
        if let Some(event) = last_est {
            let event_digest = event.event_message.digest().unwrap();
            Some(EventSeal::new(
                event.event_message.data.get_prefix(),
                event.event_message.data.get_sn(),
                event_digest.into(),
            ))
        } else {
            None
        }
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
        if let Some(events) = self
            .events_db
            .get_kel_finalized_events(QueryParameters::Range {
                id: id.clone(),
                start: 0,
                limit: sn + 1,
            })
        {
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
        event_digest: &SelfAddressingIdentifier,
    ) -> Result<Option<KeyConfig>, Error> {
        if let Some(event) = self.get_event_at_sn(id, sn) {
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
                Ok(None)
            }
        } else {
            Ok(None)
        }
    }

    pub fn has_receipt(
        &self,
        id: &IdentifierPrefix,
        sn: u64,
        validator_pref: &IdentifierPrefix,
    ) -> Result<bool, Error> {
        Ok(
            if let Some(mut receipts) = self.events_db.get_receipts_t(QueryParameters::BySn {
                id: id.clone(),
                sn: sn,
            }) {
                receipts.any(|receipt| match receipt {
                    Transferable::Seal(event_seal, _vec) => event_seal.prefix.eq(validator_pref),
                })
            } else {
                false
            },
        )
    }

    pub fn get_nt_receipts(
        &self,
        id: &IdentifierPrefix,
        sn: u64,
        // digest: &SelfAddressingIdentifier,
    ) -> Result<Option<SignedNontransferableReceipt>, Error> {
        match self
            .events_db
            .get_receipts_nt(QueryParameters::BySn { id: id.clone(), sn })
        {
            Some(mut events) => {
                let sigs = events.next();
                // let body = Receipt::new(SerializationFormats::JSON, digest.clone(), id.clone(), sn);
                Ok(sigs)
            }
            None => Ok(None),
        }
    }

    #[cfg(feature = "query")]
    pub fn get_last_ksn_reply(
        &self,
        creator_prefix: &IdentifierPrefix,
        signer_prefix: &IdentifierPrefix,
    ) -> Option<SignedReply> {
        self.events_db.get_reply(creator_prefix, signer_prefix)
    }

    /// Compute state at event given by sn and digest.
    ///
    /// Return current state for event identifier prefix, sn and
    /// digest.
    pub fn compute_state_at_event(
        &self,
        sn: u64,
        id: &IdentifierPrefix,
        event_digest: &SelfAddressingIdentifier,
    ) -> Result<Option<IdentifierState>, Error> {
        let new_state = self.compute_state_at_sn(id, sn)?;
        if let Some(ref state) = new_state {
            let last_event_digest: SelfAddressingIdentifier =
                state.last_event_digest.clone().into();
            if last_event_digest.eq(event_digest) {
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
        event_digest: &SelfAddressingIdentifier,
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
        if let Some(state) = compute_state(self.events_db.clone(), id) {
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
            .get_state(prefix)
            .ok_or_else(|| Error::SemanticError("No state in db".into()))?;
        Ok(KeyStateNotice::new_ksn(state, format))
    }
}
