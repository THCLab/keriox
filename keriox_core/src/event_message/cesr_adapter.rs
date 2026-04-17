use std::convert::{TryFrom, TryInto};

use cesrox::{
    group::Group,
    payload::{parse_payload, Payload},
    primitives::IndexedSignature as CesrIndexedSignature,
    value::Value,
};
use said::{version::format::SerializationFormats, SelfAddressingIdentifier};
use serde::{Deserialize, Serialize};

use crate::event::{
    event_data::EventData,
    receipt::Receipt,
    sections::seal::{EventSeal, SourceSeal},
    KeyEvent,
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
    #[error("Cesr error")]
    CesrError(String),
    #[error("Deserialize error: {0}")]
    DeserializeError(String),
    #[error("Wrong attachment: {0}")]
    AttachmentError(String),
    #[error("Wrong event type: {0}")]
    WrongEventType(String),
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

fn flatten_universal_groups(values: Vec<Value>) -> (Option<Payload>, Vec<Group>) {
    let mut payload = None;
    let mut groups = vec![];
    for v in values {
        match v {
            Value::Payload(p) => payload = Some(p),
            Value::SpecificGroup(g) => {
                groups.push(g);
            }
            Value::UniversalGroup(_code, inner) => {
                let (_inner_payload, inner_groups) = flatten_universal_groups(inner);
                if _inner_payload.is_some() && payload.is_none() {
                    payload = _inner_payload;
                }
                groups.extend(inner_groups);
            }
            _ => {}
        }
    }
    (payload, groups)
}

impl TryFrom<&[u8]> for CesrMessage {
    type Error = ParseError;

    fn try_from(stream: &[u8]) -> Result<Self, Self::Error> {
        parse_cesr_stream(stream)
    }
}

pub fn parse_cesr_stream_many(stream: &[u8]) -> Result<Vec<CesrMessage>, ParseError> {
    let text = std::str::from_utf8(stream).map_err(|e| ParseError::CesrError(e.to_string()))?;
    let (_rest, values) =
        cesrox::parse_all(text).map_err(|e| ParseError::CesrError(e.to_string()))?;

    let mut messages = vec![];
    let mut current_payload: Option<Payload> = None;
    let mut current_groups: Vec<Group> = vec![];

    for v in values {
        match v {
            Value::Payload(p) => {
                if let Some(payload) = current_payload.take() {
                    messages.push(CesrMessage {
                        payload,
                        attachments: std::mem::take(&mut current_groups),
                    });
                }
                current_payload = Some(p);
            }
            Value::SpecificGroup(g) => {
                current_groups.push(g);
            }
            Value::UniversalGroup(_code, inner) => {
                let (inner_payload, inner_groups) = flatten_universal_groups(inner);
                if let Some(p) = inner_payload {
                    if let Some(payload) = current_payload.take() {
                        messages.push(CesrMessage {
                            payload,
                            attachments: std::mem::take(&mut current_groups),
                        });
                    }
                    current_payload = Some(p);
                }
                current_groups.extend(inner_groups);
            }
            _ => {}
        }
    }

    if let Some(payload) = current_payload {
        messages.push(CesrMessage {
            payload,
            attachments: current_groups,
        });
    }

    Ok(messages)
}

pub fn parse_cesr_stream(stream: &[u8]) -> Result<CesrMessage, ParseError> {
    let text = std::str::from_utf8(stream).map_err(|e| ParseError::CesrError(e.to_string()))?;
    let (_rest, values) =
        cesrox::parse_all(text).map_err(|e| ParseError::CesrError(e.to_string()))?;

    let (payload, groups) = flatten_universal_groups(values);
    let payload = payload.ok_or_else(|| ParseError::CesrError("No payload found".into()))?;

    Ok(CesrMessage {
        payload,
        attachments: groups,
    })
}

pub fn parse_cesr_stream_extra(stream: &[u8]) -> Result<(&str, CesrMessage), ParseError> {
    let text = std::str::from_utf8(stream).map_err(|e| ParseError::CesrError(e.to_string()))?;
    let (rest, values) =
        cesrox::parse_all(text).map_err(|e| ParseError::CesrError(e.to_string()))?;

    let (payload, groups) = flatten_universal_groups(values);
    let payload = payload.ok_or_else(|| ParseError::CesrError("No payload found".into()))?;

    Ok((
        rest,
        CesrMessage {
            payload,
            attachments: groups,
        },
    ))
}

pub fn parse_event_type(input: &[u8]) -> Result<EventType, ParseError> {
    parse_payload(input)
        .map_err(|e| ParseError::CesrError(e.to_string()))?
        .1
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
        Group::AnchoringSeals(vec![(
            seal.prefix.clone().into(),
            seal.sn,
            event_digest.into(),
        )]),
        Group::IndexedControllerSignatures(sigs),
    ]
}

impl From<&SignedEventMessage> for CesrMessage {
    fn from(ev: &SignedEventMessage) -> Self {
        let mut attachments: Vec<Group> =
            if let Some(SourceSeal { sn, digest }) = ev.delegator_seal.clone() {
                vec![Group::SourceSealCouples(vec![(sn, digest.said.into())])]
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
                        .map(|(bp, sp)| (bp.clone().into(), sp.clone().into()))
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
            Payload::JSON(event) => serde_json::from_slice(&event),
            Payload::CBOR(_event) => todo!(),
            Payload::MGPK(_event) => todo!(),
        };
        event.map_err(|e| ParseError::DeserializeError(e.to_string()))
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

    let (id, sn, digest) = seals.first()?;
    let seal = EventSeal::new(
        id.clone().into(),
        *sn,
        SelfAddressingIdentifier::from(digest.clone()),
    );
    let converted_sigs = sigs.into_iter().map(|sig| sig.clone().into()).collect();
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
            let signer = couplets[0].0.clone();
            let signature = couplets[0].1.clone();
            Ok(Op::Reply(SignedReply::new_nontrans(
                rpy,
                signer.into(),
                signature.into(),
            )))
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
    mut attachments: Vec<Group>,
) -> Result<Notice, ParseError> {
    match event_message.data.get_event_data() {
        EventData::Dip(_) | EventData::Drt(_) => {
            let (att1, att2) = (
                attachments
                    .pop()
                    .ok_or_else(|| ParseError::AttachmentError("Missing attachment".into()))?,
                attachments.pop(),
            );

            let (seals, sigs) = match (att1, att2) {
                (
                    Group::SourceSealCouples(seals),
                    Some(Group::IndexedControllerSignatures(sigs)),
                ) => Ok((Some(seals), sigs)),
                (
                    Group::IndexedControllerSignatures(sigs),
                    Some(Group::SourceSealCouples(seals)),
                ) => Ok((Some(seals), sigs)),
                (Group::IndexedControllerSignatures(sigs), None) => Ok((None, sigs)),
                _ => Err(ParseError::AttachmentError(
                    "Improper attachment type".into(),
                )),
            }?;

            let delegator_seal = if let Some(seal) = seals {
                match seal.len() {
                    0 => Err(ParseError::AttachmentError("Missing delegator seal".into())),
                    1 => Ok(seal.first().map(|seal| seal.clone().into())),
                    _ => Err(ParseError::AttachmentError("Too many seals".into())),
                }
            } else {
                Ok(None)
            };
            let signatures = sigs.into_iter().map(|sig| sig.into()).collect();

            Ok(Notice::Event(SignedEventMessage::new(
                &event_message,
                signatures,
                None,
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
                        Some(sigs.into_iter().map(|sig| sig.into()).collect())
                    } else {
                        None
                    }
                })
                .ok_or_else(|| {
                    ParseError::AttachmentError("Missing controller signatures attachment".into())
                })?;
            let witness_sigs: Vec<_> = signatures
                .into_iter()
                .filter_map(|att| match att {
                    Group::IndexedWitnessSignatures(indexed) => Some(Nontransferable::Indexed(
                        indexed.into_iter().map(|sig| sig.into()).collect(),
                    )),
                    Group::NontransReceiptCouples(couples) => Some(Nontransferable::Couplet(
                        couples
                            .into_iter()
                            .map(|(bp, sp)| (bp.into(), sp.into()))
                            .collect(),
                    )),
                    _ => None,
                })
                .collect();

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
    let nontransferable: Vec<_> = attachments
        .iter()
        .filter_map(|att| match att {
            Group::IndexedWitnessSignatures(sigs) => {
                let converted_signatures = sigs.iter().map(|sig| sig.clone().into()).collect();
                Some(Nontransferable::Indexed(converted_signatures))
            }
            Group::NontransReceiptCouples(couples) => Some(Nontransferable::Couplet(
                couples
                    .iter()
                    .map(|(bp, sp)| (bp.clone().into(), sp.clone().into()))
                    .collect(),
            )),
            _ => None,
        })
        .collect();

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
                let seal = EventSeal::new(
                    seal.0.clone().into(),
                    seal.1,
                    SelfAddressingIdentifier::from(seal.2.clone()),
                );
                i += 1;
                let indexed_sigs = if i < attachments.len() {
                    if let Group::IndexedControllerSignatures(sigs) = &attachments[i] {
                        sigs.iter().map(|s| s.clone().into()).collect()
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
                let indexed_sigs: Vec<_> = sigs.iter().map(|s| s.clone().into()).collect();
                signatures.push(Signature::Transferable(
                    SignerData::JustSignatures,
                    indexed_sigs,
                ));
                i += 1;
            }
            Group::NontransReceiptCouples(couplets) => {
                let couples: Vec<_> = couplets
                    .iter()
                    .map(|(bp, sp)| (bp.clone().into(), sp.clone().into()))
                    .collect();
                signatures.push(Signature::NonTransferable(Nontransferable::Couplet(
                    couples,
                )));
                i += 1;
            }
            Group::IndexedWitnessSignatures(sigs) => {
                let indexed_sigs: Vec<_> = sigs.iter().map(|s| s.clone().into()).collect();
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
                let indexed_sigs: Vec<_> = sigs.into_iter().map(|s| s.into()).collect();
                data_signatures.push(Signature::Transferable(
                    SignerData::JustSignatures,
                    indexed_sigs,
                ));
            }
            Group::NontransReceiptCouples(couplets) => {
                let couples: Vec<_> = couplets
                    .into_iter()
                    .map(|(bp, sp)| (bp.into(), sp.into()))
                    .collect();
                data_signatures.push(Signature::NonTransferable(Nontransferable::Couplet(
                    couples,
                )));
            }
            Group::AnchoringSeals(seals) => {
                let seal = seals.into_iter().next().ok_or_else(|| {
                    ParseError::AttachmentError("Empty AnchoringSeals in data sigs".into())
                })?;
                let seal = EventSeal::new(
                    seal.0.into(),
                    seal.1,
                    SelfAddressingIdentifier::from(seal.2),
                );
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
    fn test_signed_event() {
        let stream = br#"{"v":"KERI10JSON0001e7_","t":"icp","d":"EBfxc4RiVY6saIFmUfEtETs1FcqmktZW88UkbnOg0Qen","i":"EBfxc4RiVY6saIFmUfEtETs1FcqmktZW88UkbnOg0Qen","s":"0","kt":"2","k":["DErocgXD2RGSyvn3MObcx59jeOsEQhv2TqHirVkzrp0Q","DFXLiTjiRdSBPLL6hLa0rskIxk3dh4XwJLfctkJFLRSS","DE9YgIQVgpLwocTVrG8tidKScsQSMWwLWywNC48fhq4f"],"nt":"2","n":["EDJk5EEpC4-tQ7YDwBiKbpaZahh1QCyQOnZRF7p2i8k8","EAXfDjKvUFRj-IEB_o4y-Y_qeJAjYfZtOMD9e7vHNFss","EN8l6yJC2PxribTN0xfri6bLz34Qvj-x3cNwcV3DvT2m"],"bt":"0","b":[],"c":[],"a":[]}-AADAAD4SyJSYlsQG22MGXzRGz2PTMqpkgOyUfq7cS99sC2BCWwdVmEMKiTEeWe5kv-l_d9auxdadQuArLtAGEArW8wEABD0z_vQmFImZXfdR-0lclcpZFfkJJJNXDcUNrf7a-mGsxNLprJo-LROwDkH5m7tVrb-a1jcor2dHD9Jez-r4bQIACBFeU05ywfZycLdR0FxCvAR9BfV9im8tWe1DglezqJLf-vHRQSChY1KafbYNc96hYYpbuN90WzuCRMgV8KgRsEC"#;
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
        let stream = br#"{"v":"KERI10JSON0000c9_","t":"qry","d":"E-WvgxrllmjGFhpn0oOiBkAVz3-dEm3bbiV_5qwj81xo","dt":"2021-01-01T00:00:00.000000+00:00","r":"log","rr":"","q":{"i":"DyvCLRr5luWmp7keDvDuLP0kIqcyBYq79b3Dho1QvrjI"}}-AABAAuISeZIVO_wXjIrGJ-VcVMxr285OkKzAqVEQqVPFx8Ht2A9GQFB-zRA18J1lpqVphOnnXbTc51WR4uAvK90EHBg"#;
        // Truncated stream parses but with no attachments
        let se = super::parse_cesr_stream(&stream[..stream.len() - 1]);
        assert!(se.is_ok());
        assert!(se.unwrap().attachments.is_empty());
        // Full stream parses with attachments
        let se = super::parse_cesr_stream(stream);
        assert!(se.is_ok());
        assert!(!se.unwrap().attachments.is_empty());
    }

    #[test]
    fn test_signed_events_stream() {
        let kerl_str= br#"{"v":"KERI10JSON000120_","t":"icp","d":"EG4EuTsxPiRM7soX10XXzNsS1KqXKUp8xsQ-kW_tWHoI","i":"DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA","s":"0","kt":"1","k":["DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA"],"n":"EPYuj8mq_PYYsoBKkzX1kxSPGYBWaIya3slgCOyOtlqU","bt":"0","b":[],"c":[],"a":[]}-AABAA0aSisI4ZZTH_6JCqsvAsEpuf_Jq6bDbvPWj_eCDnAGbSARqYHipNs-9W7MHnwnMfIXwLpcoJkKGrQ-SiaklhAw{"v":"KERI10JSON000155_","t":"rot","d":"Ej30AgJV14mTTs427F3kILLrP_l03a27APg2FBO0-QtA","i":"DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA","s":"1","p":"EG4EuTsxPiRM7soX10XXzNsS1KqXKUp8xsQ-kW_tWHoI","kt":"1","k":["DVcuJOOJF1IE8svqEtrSuyQjGTd2HhfAkt9y2QkUtFJI"],"n":"E-dapdcC6XR1KWmWDsNl4J_OxcGxNZw1Xd95JH5a34fI","bt":"0","br":[],"ba":[],"a":[]}-AABAAwoiqt07w2UInzzo2DmtwkBfqX1-tTO4cYk_7YdlbJ95qA7PO5sEUkER8fZySQMNCVh64ruAh1yoew3TikwVGAQ{"v":"KERI10JSON000155_","t":"rot","d":"EmtXXRjyz6IdeX4201BgXKRDBm74gGqJF2r2umMMAL6I","i":"DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA","s":"2","p":"Ej30AgJV14mTTs427F3kILLrP_l03a27APg2FBO0-QtA","kt":"1","k":["DT1iAhBWCkvChxNWsby2J0pJyxBIxbAtbLA0Ljx-Grh8"],"n":"EKrLE2h2nh3ClyJNEjKaikHWT7G-ngimNpK-QgVQv9As","bt":"0","br":[],"ba":[],"a":[]}-AABAAW_RsDfAcHkknyzh9oeliH90KGPJEI8AP3rJPyuTnpVg8yOVtSIp_JFlyRwjV5SEQOqddAcRV6JtaQO8oXtWFCQ{"v":"KERI10JSON0000cb_","t":"ixn","d":"EY7E4RJXPe7FF1zQPbpSMIY-TYz9eAmNIhuprPYqTQ5o","i":"DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA","s":"3","p":"EmtXXRjyz6IdeX4201BgXKRDBm74gGqJF2r2umMMAL6I","a":[]}-AABAAlB0Ui5NHJpcifXUB6bAutmpZkhSgwxyI5jEZ2JGVBgTI02sC0Ugbq3q0EpOae7ruXW-eabUz2s0FAs26jGwVBg{"v":"KERI10JSON0000cb_","t":"ixn","d":"ENVzbZieVIjYLYkPWQy0gfua11KqdRG-oku5Ut8Dl6hU","i":"DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA","s":"4","p":"EY7E4RJXPe7FF1zQPbpSMIY-TYz9eAmNIhuprPYqTQ5o","a":[]}-AABAAWITFg460TXvYvxxzN62vpqpLs-vGgeGAbd-onY3DYxd5e3AljHh85pTum4Ha48F5dui9IVYqYvuYJCG8p8KvDw{"v":"KERI10JSON000155_","t":"rot","d":"E6wrLhilpPo4ePq7m7ZccEcKjwPD2q9mqzLUb_aO2Hi0","i":"DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA","s":"5","p":"ENVzbZieVIjYLYkPWQy0gfua11KqdRG-oku5Ut8Dl6hU","kt":"1","k":["DKPE5eeJRzkRTMOoRGVd2m18o8fLqM2j9kaxLhV3x8AQ"],"nt":"1","n":["EAYqAyYI6FqMrmMjmDSJVbfJjpKCS6mkzF7V3VcyzFCQ"],"bt":"0","br":[],"ba":[],"a":[]}-AABAAwOLC3kPAV22hL1JRYbkjNI62NT4VhR6W7x2FcZ-xtW7g4diCFx46YTMeF_-TDRaHJ1zyOhR5DYjkSKBDFoFCgA"#;
        let text = std::str::from_utf8(kerl_str).unwrap();
        let (rest, messages) = cesrox::parse_all(text).unwrap();

        assert!(rest.is_empty());
        assert_eq!(messages.len(), 12);
    }
}
