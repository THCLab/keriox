use std::convert::{TryFrom, TryInto};

use cesrox::{
    group::{Group, SealSourceCouple},
    payload::{parse_payload, Payload},
    primitives::{AnchoringEventSeal, IndexedSignature as CesrIndexedSignature},
    universal_codes::{UniversalCode, UniversalGroupCode},
    value::Value,
};
use said::version::format::SerializationFormats;
use serde::{Deserialize, Serialize};

use crate::{
    event::{event_data::EventData, receipt::Receipt, sections::seal::EventSeal, KeyEvent},
    prefix::{
        cesr_adapter::{from_receipt_couple, receipt_couple},
        IndexedSignature,
    },
};

#[cfg(feature = "query")]
use crate::event_message::signed_event_message::Op;

#[cfg(feature = "query")]
use super::signature::signatures_into_groups;
#[cfg(feature = "query")]
use crate::query::{
    query_event::SignedQueryMessage,
    query_event::{QueryEvent, SignedKelQuery},
    reply_event::{ReplyEvent, SignedReply},
};

#[cfg(feature = "mailbox")]
use crate::{
    event_message::signature,
    mailbox::exchange::{ExchangeMessage, SignedExchange},
    query::mailbox::{MailboxQuery, SignedMailboxQuery},
};

use super::{
    msg::{KeriEvent, TypedEvent},
    signature::Nontransferable,
    signed_event_message::{
        Message, Notice, SignedEventMessage, SignedNontransferableReceipt,
        SignedTransferableReceipt,
    },
    Typeable,
};

#[derive(Debug, thiserror::Error, Serialize, Deserialize)]
pub enum ParseError {
    #[error("Cesr error: {0}")]
    CesrError(String),
    #[error("Deserialize error: {0}")]
    DeserializeError(String),
    #[error("Wrong attachment: {0}")]
    AttachmentError(String),
    #[error("Wrong event type: {0}")]
    WrongEventType(String),
}

impl From<crate::prefix::error::Error> for ParseError {
    fn from(e: crate::prefix::error::Error) -> Self {
        ParseError::AttachmentError(e.to_string())
    }
}

pub fn indexed_signatures(
    sigs: impl IntoIterator<Item = CesrIndexedSignature>,
) -> Result<Vec<IndexedSignature>, ParseError> {
    sigs.into_iter()
        .map(|sig| IndexedSignature::try_from(sig).map_err(ParseError::from))
        .collect()
}

pub struct CesrMessage {
    pub payload: Payload,
    pub attachments: Vec<Group>,
}

impl CesrMessage {
    pub fn to_cesr(&self) -> Result<Vec<u8>, ()> {
        let mut result = self.payload.to_vec();
        for att in &self.attachments {
            result.extend_from_slice(att.to_cesr_str().as_bytes());
        }
        Ok(result)
    }
}

/// Messages being assembled from parsed CESR values: each body starts a new
/// message, and the groups after it are its attachments.
#[derive(Default)]
struct Messages {
    done: Vec<CesrMessage>,
    current: Option<CesrMessage>,
}

impl Messages {
    fn body(&mut self, payload: Payload) {
        self.done.extend(self.current.take());
        self.current = Some(CesrMessage {
            payload,
            attachments: vec![],
        });
    }

    fn attachment(&mut self, group: Group) -> Result<(), ParseError> {
        self.current
            .as_mut()
            .ok_or_else(|| ParseError::AttachmentError("attachment before any message".into()))?
            .attachments
            .push(group);
        Ok(())
    }

    /// Adds `values`, entering the universal groups that frame messages and
    /// their attachments. Anything that is not a message body or an
    /// attachment, such as a native CESR body, is an error rather than
    /// being skipped, so no message is lost silently.
    fn add(&mut self, values: Vec<Value>) -> Result<(), ParseError> {
        for value in values {
            match value {
                Value::Payload(payload) => self.body(payload),
                Value::SpecificGroup(group) => self.attachment(group)?,
                Value::VersionGenus(_) => {}
                Value::UniversalGroup(UniversalGroupCode::Genus(_), inner) => self.add(inner)?,
                Value::UniversalGroup(UniversalGroupCode::Group { code, .. }, inner) => {
                    match code {
                        UniversalCode::GenericGroup
                        | UniversalCode::BodyWithAttachments
                        | UniversalCode::Attachments => self.add(inner)?,
                        UniversalCode::NonNativeBody => {
                            let enclosed = Value::UniversalGroup(
                                UniversalGroupCode::Group { code, quadlets: 0 },
                                inner,
                            );
                            let payload = enclosed
                                .enclosed_payload()
                                .map_err(|e| ParseError::CesrError(e.to_string()))?;
                            self.body(payload)
                        }
                        UniversalCode::FixBody | UniversalCode::MapBody => {
                            return Err(ParseError::DeserializeError(
                                "native CESR message bodies are not supported".into(),
                            ))
                        }
                        other => {
                            return Err(ParseError::CesrError(format!(
                                "unexpected {other:?} group in a message stream"
                            )))
                        }
                    }
                }
                other => {
                    return Err(ParseError::CesrError(format!(
                        "unexpected value outside a message: {}",
                        String::from_utf8_lossy(&other.to_cesr())
                    )))
                }
            }
        }
        Ok(())
    }

    fn finish(mut self) -> Vec<CesrMessage> {
        self.done.extend(self.current.take());
        self.done
    }
}

/// Groups parsed CESR values into messages with their attachments.
fn messages(values: Vec<Value>) -> Result<Vec<CesrMessage>, ParseError> {
    let mut messages = Messages::default();
    messages.add(values)?;
    Ok(messages.finish())
}

/// The only message in `values`.
fn single_message(values: Vec<Value>) -> Result<CesrMessage, ParseError> {
    let mut all = messages(values)?;
    match all.len() {
        1 => Ok(all.remove(0)),
        0 => Err(ParseError::CesrError("No payload found".into())),
        n => Err(ParseError::CesrError(format!(
            "expected one message, found {n}"
        ))),
    }
}

impl TryFrom<&[u8]> for CesrMessage {
    type Error = ParseError;

    fn try_from(stream: &[u8]) -> Result<Self, Self::Error> {
        parse_cesr_stream(stream)
    }
}

pub fn parse_cesr_stream_many(stream: &[u8]) -> Result<Vec<CesrMessage>, ParseError> {
    let values = cesrox::parse(stream).map_err(|e| ParseError::CesrError(e.to_string()))?;
    messages(values)
}

pub fn parse_cesr_stream(stream: &[u8]) -> Result<CesrMessage, ParseError> {
    let values = cesrox::parse(stream).map_err(|e| ParseError::CesrError(e.to_string()))?;
    single_message(values)
}

/// Parses the CESR values at the start of `stream` and returns the part of
/// the stream that is not CESR, with the message.
pub fn parse_cesr_stream_extra(stream: &[u8]) -> Result<(&[u8], CesrMessage), ParseError> {
    let mut parsed = cesrox::values(stream);
    let values: Vec<_> = parsed.by_ref().map_while(Result::ok).collect();
    let rest = parsed.remaining();

    Ok((rest, single_message(values)?))
}

pub fn parse_event_type(input: &[u8]) -> Result<EventType, ParseError> {
    parse_payload(input)
        .map_err(|e| ParseError::CesrError(e.to_string()))?
        .0
        .try_into()
}

#[derive(Clone, Debug, PartialEq, Deserialize)]
#[serde(untagged)]
pub enum EventType {
    KeyEvent(KeriEvent<KeyEvent>),
    Receipt(Receipt),
    #[cfg(feature = "mailbox")]
    Exn(ExchangeMessage),
    #[cfg(feature = "query")]
    Qry(QueryEvent),
    #[cfg(feature = "mailbox")]
    MailboxQry(MailboxQuery),
    #[cfg(any(feature = "query", feature = "oobi"))]
    Rpy(ReplyEvent),
}

impl EventType {
    pub fn serialize(&self) -> Result<Vec<u8>, crate::error::Error> {
        match self {
            EventType::KeyEvent(event) => event.encode(),
            EventType::Receipt(rcp) => rcp.encode(),
            #[cfg(feature = "query")]
            EventType::Qry(qry) => qry.encode(),
            #[cfg(feature = "query")]
            EventType::Rpy(rpy) => rpy.encode(),
            #[cfg(feature = "mailbox")]
            EventType::Exn(exn) => exn.encode(),
            #[cfg(feature = "mailbox")]
            EventType::MailboxQry(qry) => qry.encode(),
        }
    }
}

fn encode_transferable_seal(seal: &EventSeal, sigs: Vec<CesrIndexedSignature>) -> Vec<Group> {
    let event_digest = seal.event_digest();
    vec![
        Group::AnchoringSeals(vec![AnchoringEventSeal {
            prefix: seal.prefix.clone().into(),
            sn: seal.sn.into(),
            digest: event_digest.into(),
        }]),
        Group::IndexedControllerSignatures(sigs),
    ]
}

impl From<&SignedEventMessage> for CesrMessage {
    fn from(ev: &SignedEventMessage) -> Self {
        let mut attachments: Vec<Group> = if let Some(seal) = ev.delegator_seal.clone() {
            vec![Group::SourceSealCouples(vec![SealSourceCouple::from(seal)])]
        } else {
            vec![]
        };
        let sigs = ev
            .signatures
            .clone()
            .into_iter()
            .map(|sig| sig.into())
            .collect();
        let signatures = Group::IndexedControllerSignatures(sigs);
        attachments.push(signatures);

        if let Some(witness_rcts) = &ev.witness_receipts {
            witness_rcts.iter().for_each(|rcts| match rcts {
                Nontransferable::Indexed(indexed) => {
                    let witness_sigs: Vec<CesrIndexedSignature> =
                        indexed.iter().map(|sig| sig.clone().into()).collect();
                    attachments.push(Group::IndexedWitnessSignatures(witness_sigs))
                }
                Nontransferable::Couplet(couplets) => {
                    let couples = couplets
                        .iter()
                        .map(|(bp, sp)| receipt_couple(bp.clone(), sp.clone()))
                        .collect();
                    attachments.push(Group::NontransReceiptCouples(couples))
                }
            });
        };

        CesrMessage {
            payload: ev.event_message.clone().into(),
            attachments,
        }
    }
}

impl<T: Serialize + Clone, D: Typeable<TypeTag = T> + Serialize + Clone> From<TypedEvent<T, D>>
    for Payload
{
    fn from(pd: TypedEvent<T, D>) -> Self {
        match pd.serialization_info.kind {
            SerializationFormats::JSON => Payload::JSON(pd.encode().unwrap()),
            SerializationFormats::MGPK => Payload::MGPK(pd.encode().unwrap()),
            SerializationFormats::CBOR => Payload::CBOR(pd.encode().unwrap()),
            _ => unreachable!("events are encoded as JSON, CBOR or MessagePack"),
        }
    }
}

impl From<SignedNontransferableReceipt> for CesrMessage {
    fn from(rcp: SignedNontransferableReceipt) -> CesrMessage {
        let attachments: Vec<Group> = rcp.signatures.into_iter().map(|sig| sig.into()).collect();
        CesrMessage {
            payload: rcp.body.into(),
            attachments,
        }
    }
}

impl From<SignedTransferableReceipt> for CesrMessage {
    fn from(rcp: SignedTransferableReceipt) -> CesrMessage {
        let seal = rcp.validator_seal;
        let signatures: Vec<CesrIndexedSignature> =
            rcp.signatures.into_iter().map(|sig| sig.into()).collect();
        let attachments = encode_transferable_seal(&seal, signatures);

        CesrMessage {
            payload: rcp.body.into(),
            attachments,
        }
    }
}

#[cfg(feature = "query")]
impl From<SignedReply> for CesrMessage {
    fn from(ev: SignedReply) -> Self {
        let attachments = signatures_into_groups(&[ev.signature]);
        CesrMessage {
            payload: ev.reply.into(),
            attachments,
        }
    }
}

#[cfg(feature = "query")]
impl From<SignedKelQuery> for CesrMessage {
    fn from(ev: SignedKelQuery) -> Self {
        let groups = signatures_into_groups(&[ev.signature]);

        CesrMessage {
            payload: ev.query.into(),
            attachments: groups,
        }
    }
}

#[cfg(feature = "mailbox")]
impl From<SignedMailboxQuery> for CesrMessage {
    fn from(ev: SignedMailboxQuery) -> Self {
        let groups = signatures_into_groups(&[ev.signature]);

        CesrMessage {
            payload: ev.query.into(),
            attachments: groups,
        }
    }
}

#[cfg(feature = "query")]
impl From<SignedQueryMessage> for CesrMessage {
    fn from(ev: SignedQueryMessage) -> Self {
        match ev {
            SignedQueryMessage::KelQuery(kqry) => CesrMessage::from(kqry),
            #[cfg(feature = "mailbox")]
            SignedQueryMessage::MailboxQuery(mqry) => CesrMessage::from(mqry),
        }
    }
}

#[cfg(feature = "mailbox")]
impl From<SignedExchange> for CesrMessage {
    fn from(ev: SignedExchange) -> Self {
        let mut attachments = signature::signatures_into_groups(&ev.signature);

        let data_signatures = signature::signatures_into_groups(&ev.data_signature.1);

        let data_attachment = Group::PathedMaterialQuadruplet(ev.data_signature.0, data_signatures);
        attachments.push(data_attachment);
        CesrMessage {
            payload: ev.exchange_message.into(),
            attachments,
        }
    }
}

impl TryFrom<Payload> for EventType {
    type Error = ParseError;

    fn try_from(value: Payload) -> Result<Self, Self::Error> {
        let event: Result<EventType, _> = match value {
            Payload::JSON(event) => serde_json::from_slice(&event).map_err(|e| e.to_string()),
            Payload::CBOR(event) => serde_cbor::from_slice(&event).map_err(|e| e.to_string()),
            Payload::MGPK(event) => rmp_serde::from_slice(&event).map_err(|e| e.to_string()),
            #[allow(unreachable_patterns)]
            _ => Err("unsupported message body".to_string()),
        };
        event.map_err(ParseError::DeserializeError)
    }
}

impl TryFrom<CesrMessage> for Message {
    type Error = ParseError;

    fn try_from(value: CesrMessage) -> Result<Self, Self::Error> {
        let msg = match value.payload.try_into()? {
            EventType::KeyEvent(ev) => Message::Notice(signed_key_event(ev, value.attachments)?),
            EventType::Receipt(rct) => Message::Notice(signed_receipt(rct, value.attachments)?),
            #[cfg(feature = "query")]
            EventType::Qry(qry) => Message::Op(signed_query(qry, value.attachments)?),
            #[cfg(feature = "query")]
            EventType::Rpy(rpy) => Message::Op(signed_reply(rpy, value.attachments)?),
            #[cfg(feature = "mailbox")]
            EventType::Exn(exn) => Message::Op(signed_exchange(exn, value.attachments)?),
            #[cfg(feature = "mailbox")]
            EventType::MailboxQry(qry) => {
                Message::Op(signed_management_query(qry, value.attachments)?)
            }
        };
        Ok(msg)
    }
}

impl TryFrom<CesrMessage> for Notice {
    type Error = ParseError;

    fn try_from(value: CesrMessage) -> Result<Self, Self::Error> {
        match Message::try_from(value)? {
            Message::Notice(notice) => Ok(notice),
            #[cfg(feature = "query")]
            _ => Err(ParseError::WrongEventType(
                "Cannot convert SignedEventData to Notice".to_string(),
            )),
        }
    }
}

#[cfg(any(feature = "query", feature = "oobi"))]
impl TryFrom<CesrMessage> for Op {
    type Error = ParseError;

    fn try_from(value: CesrMessage) -> Result<Self, Self::Error> {
        let et: EventType = value.payload.try_into()?;
        match et {
            #[cfg(feature = "query")]
            EventType::Qry(qry) => signed_query(qry, value.attachments),
            #[cfg(feature = "mailbox")]
            EventType::MailboxQry(qry) => signed_management_query(qry, value.attachments),
            #[cfg(feature = "oobi")]
            EventType::Rpy(rpy) => signed_reply(rpy, value.attachments),
            #[cfg(feature = "mailbox")]
            EventType::Exn(exn) => signed_exchange(exn, value.attachments),
            _ => Err(ParseError::WrongEventType(
                "Cannot convert SignedEventData to Op".to_string(),
            )),
        }
    }
}

#[cfg(feature = "query")]
impl TryFrom<CesrMessage> for SignedQueryMessage {
    type Error = ParseError;

    fn try_from(value: CesrMessage) -> Result<Self, Self::Error> {
        match Op::try_from(value)? {
            Op::Query(qry) => Ok(qry),
            _ => Err(ParseError::WrongEventType(
                "Cannot convert SignedEventData to SignedQuery".to_string(),
            )),
        }
    }
}

#[cfg(feature = "query")]
impl TryFrom<CesrMessage> for SignedReply {
    type Error = ParseError;

    fn try_from(value: CesrMessage) -> Result<Self, Self::Error> {
        match Op::try_from(value)? {
            Op::Reply(rpy) => Ok(rpy),
            _ => Err(ParseError::WrongEventType(
                "Cannot convert SignedEventData to SignedReply".to_string(),
            )),
        }
    }
}

#[cfg(feature = "mailbox")]
impl TryFrom<CesrMessage> for SignedExchange {
    type Error = ParseError;

    fn try_from(value: CesrMessage) -> Result<Self, Self::Error> {
        match Op::try_from(value)? {
            Op::Exchange(exn) => Ok(exn),
            _ => Err(ParseError::WrongEventType(
                "Cannot convert SignedEventData to SignedExchange".to_string(),
            )),
        }
    }
}

fn decode_transferable_receipt(
    attachments: &[Group],
) -> Option<(EventSeal, Vec<crate::prefix::IndexedSignature>)> {
    let seals: Vec<_> = attachments
        .iter()
        .filter_map(|att| {
            if let Group::AnchoringSeals(seals) = att {
                Some(seals)
            } else {
                None
            }
        })
        .flatten()
        .collect();

    let sigs: Vec<_> = attachments
        .iter()
        .filter_map(|att| {
            if let Group::IndexedControllerSignatures(sigs) = att {
                Some(sigs)
            } else {
                None
            }
        })
        .flatten()
        .collect();

    if seals.is_empty() || sigs.is_empty() {
        return None;
    }

    let seal = EventSeal::try_from((*seals.first()?).clone()).ok()?;
    let converted_sigs = indexed_signatures(sigs.into_iter().cloned()).ok()?;
    Some((seal, converted_sigs))
}

#[cfg(feature = "query")]
fn signed_reply(rpy: ReplyEvent, attachments: Vec<Group>) -> Result<Op, ParseError> {
    let has_anchoring = attachments
        .iter()
        .any(|att| matches!(att, Group::AnchoringSeals(_)));

    if has_anchoring {
        if let Some((seal, sigs)) = decode_transferable_receipt(&attachments) {
            return Ok(Op::Reply(SignedReply::new_trans(rpy, seal, sigs)));
        } else {
            return Err(ParseError::AttachmentError(
                "Missing signatures for transferable reply".into(),
            ));
        }
    }

    match attachments
        .into_iter()
        .next_back()
        .ok_or_else(|| ParseError::AttachmentError("Missing attachment".into()))?
    {
        Group::NontransReceiptCouples(couplets) => {
            let (signer, signature) = from_receipt_couple(
                couplets
                    .into_iter()
                    .next()
                    .ok_or_else(|| ParseError::AttachmentError("Missing signature".into()))?,
            );
            Ok(Op::Reply(SignedReply::new_nontrans(rpy, signer, signature)))
        }
        _ => Err(ParseError::AttachmentError("Improper payload type".into())),
    }
}

#[cfg(feature = "query")]
fn signed_query(qry: QueryEvent, mut attachments: Vec<Group>) -> Result<Op, ParseError> {
    use super::signature::{get_signatures, Signature, SignerData};

    let signer = qry.get_prefix();

    let att = attachments
        .pop()
        .ok_or_else(|| ParseError::AttachmentError("Missing attachment".into()))?;
    let sigs = get_signatures(att)?;
    let signature = sigs
        .into_iter()
        .next()
        .ok_or(ParseError::AttachmentError("Missing attachment".into()))?;
    let signature = match signature {
        Signature::Transferable(SignerData::JustSignatures, indexed_sigs) => {
            Signature::Transferable(SignerData::LastEstablishment(signer), indexed_sigs)
        }
        other => other,
    };
    let qry = SignedQueryMessage::KelQuery(SignedKelQuery {
        query: qry,
        signature,
    });
    Ok(Op::Query(qry))
}

#[cfg(feature = "mailbox")]
fn signed_management_query(
    qry: MailboxQuery,
    mut attachments: Vec<Group>,
) -> Result<Op, ParseError> {
    use super::signature::{get_signatures, Signature, SignerData};
    use crate::query::mailbox::MailboxRoute;

    let signer = match &qry.data.data {
        MailboxRoute::Mbx { args, .. } => args.pre.clone(),
    };

    let att = attachments
        .pop()
        .ok_or_else(|| ParseError::AttachmentError("Missing attachment".into()))?;
    let sigs = get_signatures(att)?;
    let signature = sigs
        .into_iter()
        .next()
        .ok_or(ParseError::AttachmentError("Missing attachment".into()))?;
    let signature = match signature {
        Signature::Transferable(SignerData::JustSignatures, indexed_sigs) => {
            Signature::Transferable(SignerData::LastEstablishment(signer), indexed_sigs)
        }
        other => other,
    };

    let qry = SignedQueryMessage::MailboxQuery(SignedMailboxQuery {
        query: qry,
        signature,
    });
    Ok(Op::Query(qry))
}

fn signed_key_event(
    event_message: KeriEvent<KeyEvent>,
    attachments: Vec<Group>,
) -> Result<Notice, ParseError> {
    match event_message.data.get_event_data() {
        EventData::Dip(_) | EventData::Drt(_) => {
            // Scan all attachment groups instead of pattern-matching the
            // last two: a witnessed delegated event in a KEL stream
            // carries source-seal couples, controller signatures *and*
            // witness receipts (see `From<&SignedEventMessage> for
            // CesrMessage`), and the order/count must not matter — same
            // as the non-delegated branch below.
            let mut seals = None;
            let mut sigs = None;
            let mut witness_sigs: Vec<Nontransferable> = vec![];
            for att in attachments {
                match att {
                    Group::SourceSealCouples(s) => seals = Some(s),
                    Group::IndexedControllerSignatures(s) => sigs = Some(s),
                    Group::IndexedWitnessSignatures(indexed) => {
                        witness_sigs.push(Nontransferable::Indexed(indexed_signatures(indexed)?))
                    }
                    Group::NontransReceiptCouples(couples) => {
                        witness_sigs.push(Nontransferable::Couplet(
                            couples.into_iter().map(from_receipt_couple).collect(),
                        ))
                    }
                    _ => {}
                }
            }
            let sigs = sigs.ok_or_else(|| {
                ParseError::AttachmentError("Missing controller signatures attachment".into())
            })?;

            let delegator_seal = if let Some(seal) = seals {
                match seal.len() {
                    0 => Err(ParseError::AttachmentError("Missing delegator seal".into())),
                    1 => Ok(Some(seal[0].clone().try_into()?)),
                    _ => Err(ParseError::AttachmentError("Too many seals".into())),
                }
            } else {
                Ok(None)
            };
            let signatures = indexed_signatures(sigs)?;

            Ok(Notice::Event(SignedEventMessage::new(
                &event_message,
                signatures,
                if witness_sigs.is_empty() {
                    None
                } else {
                    Some(witness_sigs)
                },
                delegator_seal?,
            )))
        }
        _ => {
            let signatures = attachments;

            let controller_sigs = signatures
                .iter()
                .cloned()
                .find_map(|att| {
                    if let Group::IndexedControllerSignatures(sigs) = att {
                        Some(indexed_signatures(sigs))
                    } else {
                        None
                    }
                })
                .ok_or_else(|| {
                    ParseError::AttachmentError("Missing controller signatures attachment".into())
                })??;
            let witness_sigs = signatures
                .into_iter()
                .filter_map(|att| match att {
                    Group::IndexedWitnessSignatures(indexed) => {
                        Some(indexed_signatures(indexed).map(Nontransferable::Indexed))
                    }
                    Group::NontransReceiptCouples(couples) => Some(Ok(Nontransferable::Couplet(
                        couples.into_iter().map(from_receipt_couple).collect(),
                    ))),
                    _ => None,
                })
                .collect::<Result<Vec<_>, _>>()?;

            Ok(Notice::Event(SignedEventMessage::new(
                &event_message,
                controller_sigs,
                if witness_sigs.is_empty() {
                    None
                } else {
                    Some(witness_sigs)
                },
                None,
            )))
        }
    }
}

fn signed_receipt(event_message: Receipt, attachments: Vec<Group>) -> Result<Notice, ParseError> {
    let nontransferable = attachments
        .iter()
        .filter_map(|att| match att {
            Group::IndexedWitnessSignatures(sigs) => {
                Some(indexed_signatures(sigs.iter().cloned()).map(Nontransferable::Indexed))
            }
            Group::NontransReceiptCouples(couples) => Some(Ok(Nontransferable::Couplet(
                couples.iter().cloned().map(from_receipt_couple).collect(),
            ))),
            _ => None,
        })
        .collect::<Result<Vec<_>, _>>()?;

    let has_anchoring_seals = attachments
        .iter()
        .any(|att| matches!(att, Group::AnchoringSeals(_)));

    let has_nontrans = attachments.iter().any(|att| {
        matches!(att, Group::NontransReceiptCouples(_))
            || matches!(att, Group::IndexedWitnessSignatures(_))
    });

    if has_anchoring_seals {
        if let Some((seal, converted_signatures)) = decode_transferable_receipt(&attachments) {
            return Ok(Notice::TransferableRct(SignedTransferableReceipt::new(
                event_message,
                seal,
                converted_signatures,
            )));
        }
    }

    if has_nontrans {
        return Ok(Notice::NontransferableRct(SignedNontransferableReceipt {
            body: event_message,
            signatures: nontransferable,
        }));
    }

    Err(ParseError::AttachmentError("Improper payload type".into()))
}

#[cfg(feature = "mailbox")]
pub fn signed_exchange(exn: ExchangeMessage, attachments: Vec<Group>) -> Result<Op, ParseError> {
    use super::signature::{Nontransferable, Signature, SignerData};

    let pathed_idx = attachments
        .iter()
        .position(|att| matches!(att, Group::PathedMaterialQuadruplet(_, _)))
        .ok_or_else(|| ParseError::AttachmentError("Missing PathedMaterialQuadruplet".into()))?;

    let mut attachments = attachments;
    let pathed = attachments.remove(pathed_idx);

    let (path, data_sigs) = match pathed {
        Group::PathedMaterialQuadruplet(path, sigs) => (path, sigs),
        _ => unreachable!(),
    };

    let mut signatures = Vec::new();
    let mut i = 0;
    while i < attachments.len() {
        match &attachments[i] {
            Group::AnchoringSeals(seals) => {
                let seal = seals
                    .first()
                    .ok_or_else(|| ParseError::AttachmentError("Empty AnchoringSeals".into()))?;
                let seal = EventSeal::try_from(seal.clone())?;
                i += 1;
                let indexed_sigs = if i < attachments.len() {
                    if let Group::IndexedControllerSignatures(sigs) = &attachments[i] {
                        indexed_signatures(sigs.iter().cloned())?
                    } else {
                        vec![]
                    }
                } else {
                    vec![]
                };
                if !indexed_sigs.is_empty() {
                    i += 1;
                }
                signatures.push(Signature::Transferable(
                    SignerData::EventSeal(seal),
                    indexed_sigs,
                ));
            }
            Group::IndexedControllerSignatures(sigs) => {
                let indexed_sigs = indexed_signatures(sigs.iter().cloned())?;
                signatures.push(Signature::Transferable(
                    SignerData::JustSignatures,
                    indexed_sigs,
                ));
                i += 1;
            }
            Group::NontransReceiptCouples(couplets) => {
                let couples = couplets.iter().cloned().map(from_receipt_couple).collect();
                signatures.push(Signature::NonTransferable(Nontransferable::Couplet(
                    couples,
                )));
                i += 1;
            }
            Group::IndexedWitnessSignatures(sigs) => {
                let indexed_sigs = indexed_signatures(sigs.iter().cloned())?;
                signatures.push(Signature::NonTransferable(Nontransferable::Indexed(
                    indexed_sigs,
                )));
                i += 1;
            }
            _ => {
                return Err(ParseError::AttachmentError(
                    "Improper attachment type".into(),
                ));
            }
        }
    }

    let mut data_signatures = Vec::new();
    for group in data_sigs {
        match group {
            Group::IndexedControllerSignatures(sigs) => {
                let indexed_sigs = indexed_signatures(sigs)?;
                data_signatures.push(Signature::Transferable(
                    SignerData::JustSignatures,
                    indexed_sigs,
                ));
            }
            Group::NontransReceiptCouples(couplets) => {
                let couples = couplets.into_iter().map(from_receipt_couple).collect();
                data_signatures.push(Signature::NonTransferable(Nontransferable::Couplet(
                    couples,
                )));
            }
            Group::AnchoringSeals(seals) => {
                let seal = seals.into_iter().next().ok_or_else(|| {
                    ParseError::AttachmentError("Empty AnchoringSeals in data sigs".into())
                })?;
                let seal = EventSeal::try_from(seal)?;
                data_signatures.push(Signature::Transferable(SignerData::EventSeal(seal), vec![]));
            }
            _ => {
                return Err(ParseError::AttachmentError(
                    "Improper data signature attachment".into(),
                ));
            }
        }
    }

    Ok(Op::Exchange(SignedExchange {
        exchange_message: exn,
        signature: signatures,
        data_signature: (path, data_signatures),
    }))
}

#[cfg(test)]
pub mod test {
    use crate::{
        event::{receipt::Receipt, KeyEvent},
        event_message::msg::KeriEvent,
    };

    #[test]
    fn test_legacy_attachments() {
        // the same event with item counts, as written before CESR V2
        let legacy = br#"{"v":"KERI10JSON0001e7_","t":"icp","d":"EBfxc4RiVY6saIFmUfEtETs1FcqmktZW88UkbnOg0Qen","i":"EBfxc4RiVY6saIFmUfEtETs1FcqmktZW88UkbnOg0Qen","s":"0","kt":"2","k":["DErocgXD2RGSyvn3MObcx59jeOsEQhv2TqHirVkzrp0Q","DFXLiTjiRdSBPLL6hLa0rskIxk3dh4XwJLfctkJFLRSS","DE9YgIQVgpLwocTVrG8tidKScsQSMWwLWywNC48fhq4f"],"nt":"2","n":["EDJk5EEpC4-tQ7YDwBiKbpaZahh1QCyQOnZRF7p2i8k8","EAXfDjKvUFRj-IEB_o4y-Y_qeJAjYfZtOMD9e7vHNFss","EN8l6yJC2PxribTN0xfri6bLz34Qvj-x3cNwcV3DvT2m"],"bt":"0","b":[],"c":[],"a":[]}-KADAAD4SyJSYlsQG22MGXzRGz2PTMqpkgOyUfq7cS99sC2BCWwdVmEMKiTEeWe5kv-l_d9auxdadQuArLtAGEArW8wEABD0z_vQmFImZXfdR-0lclcpZFfkJJJNXDcUNrf7a-mGsxNLprJo-LROwDkH5m7tVrb-a1jcor2dHD9Jez-r4bQIACBFeU05ywfZycLdR0FxCvAR9BfV9im8tWe1DglezqJLf-vHRQSChY1KafbYNc96hYYpbuN90WzuCRMgV8KgRsEC"#;
        let stream = super::parse_cesr_stream(legacy).unwrap();
        // and written again with quadlet counts
        let v2 = stream.to_cesr().unwrap();
        assert_ne!(&v2, legacy);
        let reparsed = super::parse_cesr_stream(&v2).unwrap();
        assert_eq!(reparsed.attachments, stream.attachments);
    }

    #[test]
    fn test_signed_event() {
        let stream = br#"{"v":"KERI10JSON0001e7_","t":"icp","d":"EBfxc4RiVY6saIFmUfEtETs1FcqmktZW88UkbnOg0Qen","i":"EBfxc4RiVY6saIFmUfEtETs1FcqmktZW88UkbnOg0Qen","s":"0","kt":"2","k":["DErocgXD2RGSyvn3MObcx59jeOsEQhv2TqHirVkzrp0Q","DFXLiTjiRdSBPLL6hLa0rskIxk3dh4XwJLfctkJFLRSS","DE9YgIQVgpLwocTVrG8tidKScsQSMWwLWywNC48fhq4f"],"nt":"2","n":["EDJk5EEpC4-tQ7YDwBiKbpaZahh1QCyQOnZRF7p2i8k8","EAXfDjKvUFRj-IEB_o4y-Y_qeJAjYfZtOMD9e7vHNFss","EN8l6yJC2PxribTN0xfri6bLz34Qvj-x3cNwcV3DvT2m"],"bt":"0","b":[],"c":[],"a":[]}-KBCAAD4SyJSYlsQG22MGXzRGz2PTMqpkgOyUfq7cS99sC2BCWwdVmEMKiTEeWe5kv-l_d9auxdadQuArLtAGEArW8wEABD0z_vQmFImZXfdR-0lclcpZFfkJJJNXDcUNrf7a-mGsxNLprJo-LROwDkH5m7tVrb-a1jcor2dHD9Jez-r4bQIACBFeU05ywfZycLdR0FxCvAR9BfV9im8tWe1DglezqJLf-vHRQSChY1KafbYNc96hYYpbuN90WzuCRMgV8KgRsEC"#;
        let parsed = super::parse_cesr_stream(stream);
        assert!(parsed.is_ok());
        assert_eq!(parsed.unwrap().to_cesr().unwrap(), stream);
    }

    #[test]
    fn test_key_event_parsing() {
        let stream = br#"{"v":"KERI10JSON0000fd_","t":"icp","d":"EMW0zK3bagYPO6gx3w7Ua90f-I7x5kGIaI4Xeq9W8_As","i":"BFs8BBx86uytIM0D2BhsE5rrqVIT8ef8mflpNceHo4XH","s":"0","kt":"1","k":["BFs8BBx86uytIM0D2BhsE5rrqVIT8ef8mflpNceHo4XH"],"nt":"0","n":[],"bt":"0","b":[],"c":[],"a":[]}"#;
        let event: KeriEvent<KeyEvent> = serde_json::from_slice(stream).unwrap();
        assert_eq!(event.encode().unwrap(), stream);

        let stream = br#"{"v":"KERI10JSON000160_","t":"rot","d":"EFl8nvRCbN2xQJI75nBXp-gaXuHJw8zheVjwMN_rB-pb","i":"DFs8BBx86uytIM0D2BhsE5rrqVIT8ef8mflpNceHo4XH","s":"1","p":"EJQUyxnzIAtmZPoq9f4fExeGN0qfJmaFnUEKTwIiTBPj","kt":"1","k":["DB4GWvru73jWZKpNgMQp8ayDRin0NG0Ymn_RXQP_v-PQ"],"nt":"1","n":["EIsKL3B6Zz5ICGxCQp-SoLXjwOrdlSbLJrEn21c2zVaU"],"bt":"0","br":[],"ba":[],"a":[]}"#;
        let event: KeriEvent<KeyEvent> = serde_json::from_slice(stream).unwrap();
        assert_eq!(event.encode().unwrap(), stream);

        let stream = br#"{"v":"KERI10JSON0000cb_","t":"ixn","d":"EKKccCumVQdgxvsrSXvuTtjmS28Xqf3zRJ8T6peKgl9J","i":"DFs8BBx86uytIM0D2BhsE5rrqVIT8ef8mflpNceHo4XH","s":"2","p":"ECauhEzA4DJDXVDnNQiGQ0sKXa6sx_GgS8Ebdzm4E-kQ","a":[]}"#;
        let event: KeriEvent<KeyEvent> = serde_json::from_slice(stream).unwrap();
        assert_eq!(event.encode().unwrap(), stream);

        let stream = br#"{"v":"KERI10JSON00013a_","t":"ixn","d":"EJtQndkvwnMpVGE5oVVbLWSCm-jLviGw1AOOkzBvNwsS","i":"EA_SbBUZYwqLVlAAn14d6QUBQCSReJlZ755JqTgmRhXH","s":"1","p":"EA_SbBUZYwqLVlAAn14d6QUBQCSReJlZ755JqTgmRhXH","a":[{"i":"EHng2fV42DdKb5TLMIs6bbjFkPNmIdQ5mSFn6BTnySJj","s":"0","d":"EHng2fV42DdKb5TLMIs6bbjFkPNmIdQ5mSFn6BTnySJj"}]}"#;
        let event: KeriEvent<KeyEvent> = serde_json::from_slice(stream).unwrap();
        assert_eq!(event.encode().unwrap(), stream);

        let stream = br#"{"v":"KERI10JSON00015f_","t":"dip","d":"EHng2fV42DdKb5TLMIs6bbjFkPNmIdQ5mSFn6BTnySJj","i":"EHng2fV42DdKb5TLMIs6bbjFkPNmIdQ5mSFn6BTnySJj","s":"0","kt":"1","k":["DLitcfMnabnLt-PNCaXdVwX45wsG93Wd8eW9QiZrlKYQ"],"nt":"1","n":["EDjXvWdaNJx7pAIr72Va6JhHxc7Pf4ScYJG496ky8lK8"],"bt":"0","b":[],"c":[],"a":[],"di":"EA_SbBUZYwqLVlAAn14d6QUBQCSReJlZ755JqTgmRhXH"}"#;
        let event: KeriEvent<KeyEvent> = serde_json::from_slice(stream).unwrap();
        assert_eq!(event.encode().unwrap(), stream);

        let stream = br#"{"v":"KERI10JSON000160_","t":"drt","d":"EMBBBkaLV7i6wNgfz3giib2ItrHsr548mtIflW0Hrbuv","i":"EN3PglLbr4mJblS4dyqbqlpUa735hVmLOhYUbUztxaiH","s":"4","p":"EANkcl_QewzrRSKH2p9zUskHI462CuIMS_HQIO132Z30","kt":"1","k":["DPLt4YqQsWZ5DPztI32mSyTJPRESONvE9KbETtCVYIeH"],"nt":"1","n":["EIsKL3B6Zz5ICGxCQp-SoLXjwOrdlSbLJrEn21c2zVaU"],"bt":"0","br":[],"ba":[],"a":[]}"#;
        let event: KeriEvent<KeyEvent> = serde_json::from_slice(stream).unwrap();
        assert_eq!(event.encode().unwrap(), stream);
    }

    #[test]
    fn test_receipt_parsing() {
        let stream = br#"{"v":"KERI10JSON000091_","t":"rct","d":"EKKccCumVQdgxvsrSXvuTtjmS28Xqf3zRJ8T6peKgl9J","i":"DFs8BBx86uytIM0D2BhsE5rrqVIT8ef8mflpNceHo4XH","s":"0"}"#;
        let event = super::parse_cesr_stream(stream).unwrap();
        assert_eq!(event.to_cesr().unwrap(), stream);

        let event: Receipt = serde_json::from_slice(stream).unwrap();
        assert_eq!(event.encode().unwrap(), stream.to_vec());
    }

    #[cfg(feature = "query")]
    #[test]
    fn test_qry() {
        use std::convert::TryInto;

        use crate::event_message::cesr_adapter::EventType;

        let qry_event = br#"{"v":"KERI10JSON000105_","t":"qry","d":"EHtaQHsKzezkQUEYjMjEv6nIf4AhhR9Zy6AvcfyGCXkI","dt":"2021-01-01T00:00:00.000000+00:00","r":"logs","rr":"","q":{"s":0,"i":"EIaGMMWJFPmtXznY1IIiKDIrg-vIyge6mBl2QV8dDjI3","src":"BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo"}}"#;
        let rest = "something more".as_bytes();
        let stream = [qry_event, rest].concat();

        let (_extra, event) = super::parse_cesr_stream_extra(&stream).unwrap();
        assert!(matches!(
            event.payload.clone().try_into().unwrap(),
            EventType::Qry(_)
        ));
        assert_eq!(&event.to_cesr().unwrap(), qry_event);
    }

    #[cfg(feature = "query")]
    #[test]
    fn test_signed_qry() {
        let stream = br#"{"v":"KERI10JSON0000c9_","t":"qry","d":"EOWvgxrllmjGFhpn0oOiBkAVz3-dEm3bbiV_5qwj81xo","dt":"2021-01-01T00:00:00.000000+00:00","r":"log","rr":"","q":{"i":"DCvCLRr5luWmp7keDvDuLP0kIqcyBYq79b3Dho1QvrjI"}}-KABAACISeZIVO_wXjIrGJ-VcVMxr285OkKzAqVEQqVPFx8Ht2A9GQFB-zRA18J1lpqVphOnnXbTc51WR4uAvK90EHBg"#;
        // A stream cut off inside an attachment is rejected
        let se = super::parse_cesr_stream(&stream[..stream.len() - 1]);
        assert!(se.is_err());
        // Full stream parses with attachments
        let se = super::parse_cesr_stream(stream);
        assert!(se.is_ok());
        assert!(!se.unwrap().attachments.is_empty());
    }

    #[test]
    fn test_signed_events_stream() {
        let kerl_str= br#"{"v":"KERI10JSON000120_","t":"icp","d":"EG4EuTsxPiRM7soX10XXzNsS1KqXKUp8xsQ-kW_tWHoI","i":"DCuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA","s":"0","kt":"1","k":["DCuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA"],"n":"EPYuj8mq_PYYsoBKkzX1kxSPGYBWaIya3slgCOyOtlqU","bt":"0","b":[],"c":[],"a":[]}-KABAAAaSisI4ZZTH_6JCqsvAsEpuf_Jq6bDbvPWj_eCDnAGbSARqYHipNs-9W7MHnwnMfIXwLpcoJkKGrQ-SiaklhAw{"v":"KERI10JSON000155_","t":"rot","d":"ED30AgJV14mTTs427F3kILLrP_l03a27APg2FBO0-QtA","i":"DCuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA","s":"1","p":"EG4EuTsxPiRM7soX10XXzNsS1KqXKUp8xsQ-kW_tWHoI","kt":"1","k":["DFcuJOOJF1IE8svqEtrSuyQjGTd2HhfAkt9y2QkUtFJI"],"n":"EOdapdcC6XR1KWmWDsNl4J_OxcGxNZw1Xd95JH5a34fI","bt":"0","br":[],"ba":[],"a":[]}-KABAAAoiqt07w2UInzzo2DmtwkBfqX1-tTO4cYk_7YdlbJ95qA7PO5sEUkER8fZySQMNCVh64ruAh1yoew3TikwVGAQ{"v":"KERI10JSON000155_","t":"rot","d":"EGtXXRjyz6IdeX4201BgXKRDBm74gGqJF2r2umMMAL6I","i":"DCuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA","s":"2","p":"ED30AgJV14mTTs427F3kILLrP_l03a27APg2FBO0-QtA","kt":"1","k":["DD1iAhBWCkvChxNWsby2J0pJyxBIxbAtbLA0Ljx-Grh8"],"n":"EKrLE2h2nh3ClyJNEjKaikHWT7G-ngimNpK-QgVQv9As","bt":"0","br":[],"ba":[],"a":[]}-KABAAC_RsDfAcHkknyzh9oeliH90KGPJEI8AP3rJPyuTnpVg8yOVtSIp_JFlyRwjV5SEQOqddAcRV6JtaQO8oXtWFCQ{"v":"KERI10JSON0000cb_","t":"ixn","d":"EI7E4RJXPe7FF1zQPbpSMIY-TYz9eAmNIhuprPYqTQ5o","i":"DCuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA","s":"3","p":"EGtXXRjyz6IdeX4201BgXKRDBm74gGqJF2r2umMMAL6I","a":[]}-KABAABB0Ui5NHJpcifXUB6bAutmpZkhSgwxyI5jEZ2JGVBgTI02sC0Ugbq3q0EpOae7ruXW-eabUz2s0FAs26jGwVBg{"v":"KERI10JSON0000cb_","t":"ixn","d":"ENVzbZieVIjYLYkPWQy0gfua11KqdRG-oku5Ut8Dl6hU","i":"DCuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA","s":"4","p":"EI7E4RJXPe7FF1zQPbpSMIY-TYz9eAmNIhuprPYqTQ5o","a":[]}-KABAACITFg460TXvYvxxzN62vpqpLs-vGgeGAbd-onY3DYxd5e3AljHh85pTum4Ha48F5dui9IVYqYvuYJCG8p8KvDw{"v":"KERI10JSON000155_","t":"rot","d":"EKwrLhilpPo4ePq7m7ZccEcKjwPD2q9mqzLUb_aO2Hi0","i":"DCuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA","s":"5","p":"ENVzbZieVIjYLYkPWQy0gfua11KqdRG-oku5Ut8Dl6hU","kt":"1","k":["DKPE5eeJRzkRTMOoRGVd2m18o8fLqM2j9kaxLhV3x8AQ"],"nt":"1","n":["EAYqAyYI6FqMrmMjmDSJVbfJjpKCS6mkzF7V3VcyzFCQ"],"bt":"0","br":[],"ba":[],"a":[]}-KABAAAOLC3kPAV22hL1JRYbkjNI62NT4VhR6W7x2FcZ-xtW7g4diCFx46YTMeF_-TDRaHJ1zyOhR5DYjkSKBDFoFCgA"#;
        let messages = cesrox::parse(kerl_str).unwrap();

        assert_eq!(messages.len(), 12);
    }

    /// A signed inception in `format`, written as a CESR stream.
    #[cfg(feature = "storage-redb")]
    fn signed_inception(
        format: said::version::format::SerializationFormats,
    ) -> (crate::prefix::IdentifierPrefix, Vec<u8>) {
        use crate::{
            event::{
                event_data::InceptionEvent,
                sections::{
                    key_config::{nxt_commitment, KeyConfig},
                    threshold::SignatureThreshold,
                },
            },
            event_message::signed_event_message::{Message, Notice},
            prefix::{BasicPrefix, IndexedSignature, SelfSigningPrefix},
            signer::Signer,
        };
        use said::derivation::{HashFunction, HashFunctionCode};

        let signer = Signer::new();
        let derivation: HashFunction = HashFunctionCode::Blake3_256.into();
        let key_config = KeyConfig::new(
            vec![BasicPrefix::Ed25519(signer.public_key())],
            nxt_commitment(
                SignatureThreshold::Simple(1),
                &[BasicPrefix::Ed25519(Signer::new().public_key())],
                &derivation,
            ),
            Some(SignatureThreshold::Simple(1)),
        );
        let icp = InceptionEvent::new(key_config, None, None)
            .incept_self_addressing(derivation, format)
            .unwrap();
        let signature =
            SelfSigningPrefix::Ed25519Sha512(signer.sign(icp.encode().unwrap()).unwrap());
        let signed = icp.sign(
            vec![IndexedSignature::new_both_same(signature, 0)],
            None,
            None,
        );
        let stream = Message::Notice(Notice::Event(signed)).to_cesr().unwrap();
        (icp.data.get_prefix(), stream)
    }

    #[cfg(feature = "storage-redb")]
    #[test]
    fn test_cbor_and_mgpk_bodies() {
        use std::sync::Arc;

        use crate::{
            actor::{parse_notice_stream, process_notice},
            database::redb::RedbDatabase,
            processor::{basic_processor::BasicProcessor, event_storage::EventStorage},
        };
        use said::version::format::SerializationFormats;

        for format in [SerializationFormats::CBOR, SerializationFormats::MGPK] {
            let (id, stream) = signed_inception(format);
            let path = tempfile::NamedTempFile::new().unwrap();
            let db = Arc::new(RedbDatabase::new(path.path()).unwrap());
            let processor = BasicProcessor::new(db.clone(), None);
            for notice in parse_notice_stream(&stream).unwrap() {
                process_notice(notice, &processor).unwrap();
            }
            let state = EventStorage::new(db).get_state(&id).unwrap();
            assert_eq!(state.sn, 0, "{format:?}");
        }
    }

    #[cfg(feature = "storage-redb")]
    #[test]
    fn test_enclosed_body() {
        use cesrox::value::Value;
        use said::version::format::SerializationFormats;

        let (_id, stream) = signed_inception(SerializationFormats::JSON);
        let message = super::parse_cesr_stream(&stream).unwrap();
        // the same message with its body enclosed in a -H group
        let mut enclosed = Value::non_native_body(&message.payload).unwrap().to_cesr();
        for group in &message.attachments {
            enclosed.extend(group.to_cesr_str().into_bytes());
        }
        let reparsed = super::parse_cesr_stream(&enclosed).unwrap();
        assert_eq!(reparsed.payload, message.payload);
        assert_eq!(reparsed.attachments, message.attachments);
    }

    #[test]
    fn test_values_that_are_not_messages_are_rejected() {
        use super::{parse_cesr_stream_many, ParseError};

        // a native CESR body (an empty -F group)
        assert!(matches!(
            parse_cesr_stream_many(b"-FAA"),
            Err(ParseError::DeserializeError(_))
        ));
        // a primitive on its own
        assert!(parse_cesr_stream_many(b"DErocgXD2RGSyvn3MObcx59jeOsEQhv2TqHirVkzrp0Q").is_err());
        // an attachment with no message before it
        let signatures = "-KAWAAD4SyJSYlsQG22MGXzRGz2PTMqpkgOyUfq7cS99sC2BCWwdVmEMKiTEeWe5kv-l_d9auxdadQuArLtAGEArW8wE";
        assert!(matches!(
            parse_cesr_stream_many(signatures.as_bytes()),
            Err(ParseError::AttachmentError(_))
        ));
    }
}
