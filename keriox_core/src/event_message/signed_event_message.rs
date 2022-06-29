use std::cmp::Ordering;

use chrono::{DateTime, Duration, Local};
use serde::{ser::SerializeStruct, Deserialize, Serialize};

use super::{key_event_message::KeyEvent, serializer::to_string, EventMessage};
#[cfg(feature = "query")]
use crate::query::{query_event::SignedQuery, reply_event::SignedReply};
use crate::{
    error::Error,
    event::{
        receipt::Receipt,
        sections::seal::{EventSeal, SourceSeal},
    },
    event_parsing::{Attachment, SignedEventData},
    prefix::{AttachedSignaturePrefix, BasicPrefix, IdentifierPrefix, SelfSigningPrefix},
    state::{EventSemantics, IdentifierState},
};

#[derive(Clone, Debug, PartialEq)]
pub enum Message {
    Notice(Notice),
    Op(Op),
}

#[derive(Clone, Debug, PartialEq)]
pub enum Notice {
    Event(SignedEventMessage),
    // Rct's have an alternative appended signature structure,
    // use SignedNontransferableReceipt and SignedTransferableReceipt
    NontransferableRct(SignedNontransferableReceipt),
    TransferableRct(SignedTransferableReceipt),
}

#[derive(Clone, Debug, PartialEq)]
pub enum Op {
    #[cfg(feature = "query")]
    Reply(SignedReply),
    #[cfg(any(feature = "query", feature = "oobi"))]
    Query(SignedQuery),
}

impl From<Message> for SignedEventData {
    fn from(message: Message) -> Self {
        match message {
            Message::Notice(notice) => SignedEventData::from(notice),
            Message::Op(op) => SignedEventData::from(op),
        }
    }
}

impl From<Notice> for SignedEventData {
    fn from(notice: Notice) -> Self {
        match notice {
            Notice::Event(event) => SignedEventData::from(&event),
            Notice::NontransferableRct(rct) => SignedEventData::from(rct),
            Notice::TransferableRct(rct) => SignedEventData::from(rct),
        }
    }
}

impl From<Op> for SignedEventData {
    fn from(op: Op) -> Self {
        match op {
            #[cfg(feature = "query")]
            Op::Reply(ksn) => SignedEventData::from(ksn),
            #[cfg(feature = "query")]
            Op::Query(qry) => SignedEventData::from(qry),
        }
    }
}

impl Message {
    pub fn to_cesr(&self) -> Result<Vec<u8>, Error> {
        SignedEventData::from(self.clone()).to_cesr()
    }

    pub fn get_prefix(&self) -> IdentifierPrefix {
        match self {
            Message::Notice(notice) => notice.get_prefix(),
            Message::Op(op) => op.get_prefix(),
        }
    }
}

impl Notice {
    pub fn get_prefix(&self) -> IdentifierPrefix {
        match self {
            Notice::Event(ev) => ev.event_message.event.get_prefix(),
            Notice::NontransferableRct(rct) => rct.body.event.prefix.clone(),
            Notice::TransferableRct(rct) => rct.body.event.prefix.clone(),
        }
    }
}

impl Op {
    pub fn get_prefix(&self) -> IdentifierPrefix {
        match self {
            #[cfg(feature = "query")]
            Op::Reply(reply) => reply.reply.get_prefix(),
            #[cfg(feature = "query")]
            Op::Query(qry) => qry.query.get_prefix(),
        }
    }
}

// KERI serializer should be used to serialize this
#[derive(Debug, Clone, Deserialize)]
pub struct SignedEventMessage {
    pub event_message: EventMessage<KeyEvent>,
    #[serde(skip_serializing)]
    pub signatures: Vec<AttachedSignaturePrefix>,
    #[serde(skip_serializing)]
    pub witness_receipts: Option<Vec<AttachedSignaturePrefix>>,
    #[serde(skip_serializing)]
    pub delegator_seal: Option<SourceSeal>,
}

impl Serialize for SignedEventMessage {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        // if JSON - we pack qb64 KERI
        if serializer.is_human_readable() {
            let mut em = serializer.serialize_struct("EventMessage", 3)?;
            em.serialize_field("", &self.event_message)?;
            let att_sigs = Attachment::AttachedSignatures(self.signatures.clone());
            em.serialize_field("-", &att_sigs.to_cesr())?;
            if let Some(ref seal) = self.delegator_seal {
                let att_seal = Attachment::SealSourceCouplets(vec![seal.clone()]);
                em.serialize_field("", &att_seal.to_cesr())?;
            }

            em.end()
        // . else - we pack as it is for DB / CBOR purpose
        } else {
            let mut em = serializer.serialize_struct("SignedEventMessage", 3)?;
            em.serialize_field("event_message", &self.event_message)?;
            em.serialize_field("signatures", &self.signatures)?;
            em.serialize_field("delegator_seal", &self.delegator_seal)?;
            em.end()
        }
    }
}

impl PartialEq for SignedEventMessage {
    fn eq(&self, other: &Self) -> bool {
        self.event_message == other.event_message && self.signatures == other.signatures
    }
}

#[derive(Serialize, Deserialize)]
pub struct Timestamped<M> {
    pub timestamp: DateTime<Local>,
    pub signed_event_message: M,
}

impl<M> Timestamped<M> {
    pub fn new(event: M) -> Self {
        Self {
            timestamp: Local::now(),
            signed_event_message: event,
        }
    }

    pub fn is_stale(&self, duration: std::time::Duration) -> Result<bool, Error> {
        Ok(Local::now() - self.timestamp
            > Duration::from_std(duration)
                .map_err(|_e| Error::SemanticError("Improper duration".into()))?)
    }
}

impl From<Timestamped<SignedEventMessage>> for SignedEventMessage {
    fn from(event: Timestamped<SignedEventMessage>) -> SignedEventMessage {
        event.signed_event_message
    }
}

impl From<Timestamped<SignedNontransferableReceipt>> for SignedNontransferableReceipt {
    fn from(event: Timestamped<SignedNontransferableReceipt>) -> SignedNontransferableReceipt {
        event.signed_event_message
    }
}

impl<M> From<M> for Timestamped<M> {
    fn from(event: M) -> Timestamped<M> {
        Timestamped::new(event)
    }
}

impl<M: Clone> From<&M> for Timestamped<M> {
    fn from(event: &M) -> Timestamped<M> {
        Timestamped::new(event.clone())
    }
}

impl<M: PartialEq> PartialEq for Timestamped<M> {
    fn eq(&self, other: &Self) -> bool {
        self.signed_event_message == other.signed_event_message
    }
}

impl PartialOrd for Timestamped<SignedEventMessage> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(
            match self.signed_event_message.event_message.event.get_sn()
                == other.signed_event_message.event_message.event.get_sn()
            {
                true => Ordering::Equal,
                false => {
                    match self.signed_event_message.event_message.event.get_sn()
                        > other.signed_event_message.event_message.event.get_sn()
                    {
                        true => Ordering::Greater,
                        false => Ordering::Less,
                    }
                }
            },
        )
    }
}

impl Ord for Timestamped<SignedEventMessage> {
    fn cmp(&self, other: &Self) -> Ordering {
        match self.signed_event_message.event_message.event.get_sn()
            == other.signed_event_message.event_message.event.get_sn()
        {
            true => Ordering::Equal,
            false => match self.signed_event_message.event_message.event.get_sn()
                > other.signed_event_message.event_message.event.get_sn()
            {
                true => Ordering::Greater,
                false => Ordering::Less,
            },
        }
    }
}

impl Eq for Timestamped<SignedEventMessage> {}

pub type TimestampedSignedEventMessage = Timestamped<SignedEventMessage>;

impl SignedEventMessage {
    pub fn new(
        message: &EventMessage<KeyEvent>,
        sigs: Vec<AttachedSignaturePrefix>,
        witness_receipts: Option<Vec<AttachedSignaturePrefix>>,
        delegator_seal: Option<SourceSeal>,
    ) -> Self {
        Self {
            event_message: message.clone(),
            signatures: sigs,
            witness_receipts,
            delegator_seal,
        }
    }

    pub fn serialize(&self) -> Result<Vec<u8>, Error> {
        Ok(to_string(&self)?.as_bytes().to_vec())
    }
}

impl EventSemantics for SignedEventMessage {
    fn apply_to(&self, state: IdentifierState) -> Result<IdentifierState, Error> {
        self.event_message.apply_to(state)
    }
}

/// Signed Transferrable Receipt
///
/// Event Receipt which is suitable for creation by Transferable
/// Identifiers. Provides both the signatures and a commitment to
/// the latest establishment event of the receipt creator.
/// Mostly intended for use by Validators
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SignedTransferableReceipt {
    pub body: EventMessage<Receipt>,
    pub validator_seal: EventSeal,
    pub signatures: Vec<AttachedSignaturePrefix>,
}

impl SignedTransferableReceipt {
    pub fn new(
        message: EventMessage<Receipt>,
        event_seal: EventSeal,
        sigs: Vec<AttachedSignaturePrefix>,
    ) -> Self {
        Self {
            body: message,
            validator_seal: event_seal,
            signatures: sigs,
        }
    }
}

/// Signed Non-Transferrable Receipt
///
/// A receipt created by an Identifier of a non-transferrable type.
/// Mostly intended for use by Witnesses.
/// NOTE: This receipt has a unique structure to it's appended
/// signatures
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SignedNontransferableReceipt {
    pub body: EventMessage<Receipt>,
    pub couplets: Option<Vec<(BasicPrefix, SelfSigningPrefix)>>,
    pub indexed_sigs: Option<Vec<AttachedSignaturePrefix>>,
}

impl SignedNontransferableReceipt {
    pub fn new(
        message: &EventMessage<Receipt>,
        couplets: Option<Vec<(BasicPrefix, SelfSigningPrefix)>>,
        indexed_sigs: Option<Vec<AttachedSignaturePrefix>>,
    ) -> Self {
        Self {
            body: message.clone(),
            couplets,
            indexed_sigs,
        }
    }
}

pub type TimestampedNontransReceipt = Timestamped<SignedNontransferableReceipt>;
