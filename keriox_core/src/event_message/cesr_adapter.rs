use std::convert::{TryFrom};

use serde::Deserialize;

use crate::{
    error::Error,
    event::{
        event_data::EventData,
        receipt::Receipt,
        sections::seal::{EventSeal, SourceSeal},
    },
    event_parsing::{
        error::Error as CesrError, group::Group, primitives::IndexedSignature, ParsedData, Payload,
    },
};

#[cfg(feature = "query")]
use crate::query::{
    query_event::{QueryEvent, SignedQuery},
    reply_event::{ReplyEvent, SignedReply},
};

#[cfg(feature = "mailbox")]
use crate::mailbox::exchange::{ExchangeMessage, SignedExchange};

use super::{
    key_event_message::KeyEvent,
    signature::{self, Nontransferable, Signature},
    signed_event_message::{
        Message, Notice, Op, SignedEventMessage, SignedNontransferableReceipt,
        SignedTransferableReceipt,
    },
    EventMessage,
};

pub type ParsedEvent = ParsedData<EventType>;

impl Payload for EventType {
    fn to_vec(&self) -> Result<Vec<u8>, CesrError> {
        self.serialize()
            .map_err(|_e| CesrError::PayloadSerializationError)
    }
}

#[derive(Clone, Debug, PartialEq, Deserialize)]
#[serde(untagged)]
pub enum EventType {
    KeyEvent(EventMessage<KeyEvent>),
    Receipt(EventMessage<Receipt>),
    #[cfg(feature = "mailbox")]
    Exn(ExchangeMessage),
    #[cfg(feature = "query")]
    Qry(QueryEvent),
    #[cfg(any(feature = "query", feature = "oobi"))]
    Rpy(ReplyEvent),
}

impl EventType {
    pub fn serialize(&self) -> Result<Vec<u8>, Error> {
        match self {
            EventType::KeyEvent(event) => event.serialize(),
            EventType::Receipt(rcp) => rcp.serialize(),
            #[cfg(feature = "query")]
            EventType::Qry(qry) => qry.serialize(),
            #[cfg(feature = "query")]
            EventType::Rpy(rpy) => rpy.serialize(),
            #[cfg(feature = "mailbox")]
            EventType::Exn(exn) => exn.serialize(),
        }
    }
}

impl From<&SignedEventMessage> for ParsedData<EventType> {
    fn from(ev: &SignedEventMessage) -> Self {
        let mut attachments = if let Some(SourceSeal { sn, digest }) = ev.delegator_seal.clone() {
            vec![Group::SourceSealCouples(vec![(sn, (&digest).into())])]
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
                    let witness_sigs: Vec<IndexedSignature> =
                        indexed.into_iter().map(|sig| sig.clone().into()).collect();
                    attachments.push(Group::IndexedWitnessSignatures(witness_sigs))
                }
                Nontransferable::Couplet(couplets) => {
                    let couples = couplets
                        .into_iter()
                        .map(|(bp, sp)| (bp.clone().into(), sp.clone().into()))
                        .collect();
                    attachments.push(Group::NontransferableReceiptCouples(couples))
                }
            });
        };

        ParsedData {
            payload: EventType::KeyEvent(ev.event_message.clone()),
            attachments,
        }
    }
}

impl From<SignedNontransferableReceipt> for ParsedData<EventType> {
    fn from(rcp: SignedNontransferableReceipt) -> ParsedData<EventType> {
        let attachments = rcp.signatures.into_iter().map(|sig| sig.into()).collect();
        ParsedData {
            payload: EventType::Receipt(rcp.body),
            attachments,
        }
    }
}

impl From<SignedTransferableReceipt> for ParsedData<EventType> {
    fn from(rcp: SignedTransferableReceipt) -> ParsedData<EventType> {
        let seal = rcp.validator_seal;
        let signatures = rcp.signatures.into_iter().map(|sig| sig.into()).collect();
        let quadruple = (
            seal.prefix.into(),
            seal.sn,
            (&seal.event_digest).into(),
            signatures,
        );
        let group = Group::TransferableIndexedSigGroups(vec![quadruple]);

        ParsedData {
            payload: EventType::Receipt(rcp.body),
            attachments: vec![group],
        }
    }
}

#[cfg(feature = "query")]
impl From<SignedReply> for ParsedData<EventType> {
    fn from(ev: SignedReply) -> Self {
        let attachments = vec![ev.signature.into()];
        ParsedData {
            payload: EventType::Rpy(ev.reply),
            attachments,
        }
    }
}

#[cfg(feature = "query")]
impl From<SignedQuery> for ParsedData<EventType> {
    fn from(ev: SignedQuery) -> Self {
        let signatures = ev.signatures.into_iter().map(|sig| sig.into()).collect();
        let attachments = vec![Group::LastEstSignaturesGroups(vec![(
            ev.signer.into(),
            signatures,
        )])];

        ParsedData {
            payload: EventType::Qry(ev.query),
            attachments,
        }
    }
}

#[cfg(feature = "mailbox")]
impl From<SignedExchange> for ParsedData<EventType> {
    fn from(ev: SignedExchange) -> Self {
        let mut attachments = signature::signatures_into_groups(&ev.signature);

        let data_signatures = signature::signatures_into_groups(&ev.data_signature.1);

        let data_attachment = Group::PathedMaterialQuadruplet(ev.data_signature.0, data_signatures);
        attachments.push(data_attachment);
        ParsedData {
            payload: EventType::Exn(ev.exchange_message),
            attachments,
        }
    }
}

impl TryFrom<ParsedData<EventType>> for Message {
    type Error = Error;

    fn try_from(value: ParsedData<EventType>) -> Result<Self, Self::Error> {
        let msg = match value.payload {
            EventType::KeyEvent(ev) => Message::Notice(signed_key_event(ev, value.attachments)?),
            EventType::Receipt(rct) => Message::Notice(signed_receipt(rct, value.attachments)?),
            #[cfg(feature = "query")]
            EventType::Qry(qry) => Message::Op(signed_query(qry, value.attachments)?),
            #[cfg(any(feature = "query", feature = "oobi"))]
            EventType::Rpy(rpy) => Message::Op(signed_reply(rpy, value.attachments)?),
            #[cfg(feature = "mailbox")]
            EventType::Exn(exn) => Message::Op(signed_exchange(exn, value.attachments)?),
        };
        Ok(msg)
    }
}

impl TryFrom<ParsedData<EventType>> for Notice {
    type Error = Error;

    fn try_from(value: ParsedData<EventType>) -> Result<Self, Self::Error> {
        match Message::try_from(value)? {
            Message::Notice(notice) => Ok(notice),
            _ => Err(Error::SemanticError(
                "Cannot convert SignedEventData to Notice".to_string(),
            )),
        }
    }
}

impl TryFrom<ParsedData<EventType>> for Op {
    type Error = Error;

    fn try_from(value: ParsedData<EventType>) -> Result<Self, Self::Error> {
        match value.payload {
            #[cfg(feature = "query")]
            EventType::Qry(qry) => signed_query(qry, value.attachments),
            #[cfg(any(feature = "query", feature = "oobi"))]
            EventType::Rpy(rpy) => signed_reply(rpy, value.attachments),
            #[cfg(feature = "mailbox")]
            EventType::Exn(exn) => signed_exchange(exn, value.attachments),
            _ => Err(Error::SemanticError(
                "Cannot convert SignedEventData to Op".to_string(),
            )),
        }
    }
}

#[cfg(feature = "query")]
impl TryFrom<ParsedData<EventType>> for SignedQuery {
    type Error = Error;

    fn try_from(value: ParsedData<EventType>) -> Result<Self, Self::Error> {
        match Op::try_from(value)? {
            Op::Query(qry) => Ok(qry),
            _ => Err(Error::SemanticError(
                "Cannot convert SignedEventData to SignedQuery".to_string(),
            )),
        }
    }
}

#[cfg(feature = "query")]
impl TryFrom<ParsedData<EventType>> for SignedReply {
    type Error = Error;

    fn try_from(value: ParsedData<EventType>) -> Result<Self, Self::Error> {
        match Op::try_from(value)? {
            Op::Reply(rpy) => Ok(rpy),
            _ => Err(Error::SemanticError(
                "Cannot convert SignedEventData to SignedReply".to_string(),
            )),
        }
    }
}

#[cfg(feature = "mailbox")]
impl TryFrom<ParsedData<EventType>> for SignedExchange {
    type Error = Error;

    fn try_from(value: ParsedData<EventType>) -> Result<Self, Self::Error> {
        match Op::try_from(value)? {
            Op::Exchange(exn) => Ok(exn),
            _ => Err(Error::SemanticError(
                "Cannot convert SignedEventData to SignedExchange".to_string(),
            )),
        }
    }
}

#[cfg(any(feature = "query", feature = "oobi"))]
fn signed_reply(rpy: ReplyEvent, mut attachments: Vec<Group>) -> Result<Op, Error> {
    match attachments
        .pop()
        .ok_or_else(|| Error::SemanticError("Missing attachment".into()))?
    {
        Group::NontransferableReceiptCouples(couplets) => {
            let signer = couplets[0].0.clone();
            let signature = couplets[0].1.clone();
            Ok(Op::Reply(SignedReply::new_nontrans(
                rpy,
                signer.into(),
                signature.into(),
            )))
        }
        Group::TransferableIndexedSigGroups(data) => {
            let (prefix, sn, digest, sigs) = data
                // TODO what if more than one?
                .last()
                .ok_or_else(|| Error::SemanticError("More than one seal".into()))?
                .to_owned();
            let seal = EventSeal {
                prefix: prefix.into(),
                sn: sn,
                event_digest: digest.into(),
            };
            let sigs = sigs.into_iter().map(|sig| sig.into()).collect();
            Ok(Op::Reply(SignedReply::new_trans(rpy, seal, sigs)))
        }
        Group::Frame(atts) => signed_reply(rpy, atts),
        _ => {
            // Improper payload type
            Err(Error::SemanticError("Improper payload type".into()))
        }
    }
}

#[cfg(feature = "query")]
fn signed_query(qry: QueryEvent, mut attachments: Vec<Group>) -> Result<Op, Error> {
    match attachments
        .pop()
        .ok_or_else(|| Error::SemanticError("Missing attachment".into()))?
    {
        Group::LastEstSignaturesGroups(groups) => {
            let (signer, signatures) = groups[0].clone();
            let converted_signatures = signatures.into_iter().map(|sig| sig.into()).collect();
            Ok(Op::Query(SignedQuery {
                query: qry,
                signer: signer.into(),
                signatures: converted_signatures,
            }))
        }
        Group::Frame(atts) => signed_query(qry, atts),
        _ => {
            // Improper payload type
            Err(Error::SemanticError(
                "Improper attachments for query message".into(),
            ))
        }
    }
}

fn signed_key_event(
    event_message: EventMessage<KeyEvent>,
    mut attachments: Vec<Group>,
) -> Result<Notice, Error> {
    match event_message.event.get_event_data() {
        EventData::Dip(_) | EventData::Drt(_) => {
            let (att1, att2) = (
                attachments
                    .pop()
                    .ok_or_else(|| Error::SemanticError("Missing attachment".into()))?,
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
                _ => {
                    // Improper attachment type
                    Err(Error::SemanticError("Improper attachment type".into()))
                }
            }?;

            let delegator_seal = if let Some(seal) = seals {
                match seal.len() {
                    0 => Err(Error::SemanticError("Missing delegator seal".into())),
                    1 => Ok(seal.first().map(|seal| seal.clone().into())),
                    _ => Err(Error::SemanticError("Too many seals".into())),
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
            let signatures = if let Group::Frame(atts) = attachments
                .first()
                .cloned()
                .ok_or_else(|| Error::SemanticError("Missing attachment".into()))?
            {
                atts
            } else {
                attachments
            };
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
                    Error::SemanticError("Missing controller signatures attachment".into())
                })?;
            let witness_sigs: Vec<_> = signatures
                .into_iter()
                .filter_map(|att| match att {
                    Group::IndexedWitnessSignatures(indexed) => Some(Nontransferable::Indexed(
                        indexed.into_iter().map(|sig| sig.into()).collect(),
                    )),
                    Group::NontransferableReceiptCouples(couples) => {
                        Some(Nontransferable::Couplet(
                            couples
                                .into_iter()
                                .map(|(bp, sp)| (bp.into(), sp.into()))
                                .collect(),
                        ))
                    }
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
                // TODO parse delegator seal attachment
                None,
            )))
        }
    }
}

fn signed_receipt(
    event_message: EventMessage<Receipt>,
    mut attachments: Vec<Group>,
) -> Result<Notice, Error> {
    let nontransferable = attachments
        .iter()
        .filter_map(|att| match att {
            Group::IndexedWitnessSignatures(sigs) => {
                let converted_signatures = sigs.into_iter().map(|sig| sig.clone().into()).collect();
                Some(Nontransferable::Indexed(converted_signatures))
            }
            Group::NontransferableReceiptCouples(couples) => Some(Nontransferable::Couplet(
                couples
                    .into_iter()
                    .map(|(bp, sp)| (bp.clone().into(), sp.clone().into()))
                    .collect(),
            )),
            _ => None,
        })
        .collect();
    let att = attachments
        .pop()
        .ok_or_else(|| Error::SemanticError("Missing attachment".into()))?;

    match att {
        // Should be nontransferable receipt
        Group::NontransferableReceiptCouples(_) | Group::IndexedWitnessSignatures(_) => {
            Ok(Notice::NontransferableRct(SignedNontransferableReceipt {
                body: event_message,
                signatures: nontransferable,
            }))
        }
        Group::TransferableIndexedSigGroups(data) => {
            // Should be transferable receipt
            let (prefix, sn, event_digest, sigs) = data
                // TODO what if more than one?
                .last()
                .ok_or_else(|| Error::SemanticError("Empty seals".into()))?;
            let seal = EventSeal {
                prefix: prefix.clone().into(),
                sn: *sn,
                event_digest: event_digest.clone().into(),
            };
            let converted_signatures = sigs.into_iter().map(|sig| sig.clone().into()).collect();
            Ok(Notice::TransferableRct(SignedTransferableReceipt::new(
                event_message,
                seal,
                converted_signatures,
            )))
        }
        Group::Frame(atts) => signed_receipt(event_message, atts),
        _ => {
            // Improper payload type
            Err(Error::SemanticError("Improper payload type".into()))
        }
    }
}

#[cfg(feature = "mailbox")]
pub fn signed_exchange(exn: ExchangeMessage, attachments: Vec<Group>) -> Result<Op, Error> {
    use std::convert::TryInto;
    let mut atts = attachments.into_iter();
    let att1 = atts
        .next()
        .ok_or_else(|| Error::SemanticError("Missing attachment".into()))?;
    let att2 = atts
        .next()
        .ok_or_else(|| Error::SemanticError("Missing attachment".into()))?;

    let (path, data_sigs, signatures): (_, _, Vec<Signature>) = match (att1, att2) {
        (Group::PathedMaterialQuadruplet(path, sigs), anything)
        | (anything, Group::PathedMaterialQuadruplet(path, sigs)) => {
            (path, sigs, anything.try_into()?)
        }
        _ => return Err(Error::SemanticError("Wrong attachment".into())),
    };

    let data_signatures: Result<Vec<Signature>, Error> =
        data_sigs.into_iter().fold(Ok(vec![]), |acc, group| {
            let mut signatures: Vec<Signature> = group.try_into()?;
            let mut sigs = acc?;
            sigs.append(&mut signatures);
            Ok(sigs)
        });

    Ok(Op::Exchange(SignedExchange {
        exchange_message: exn,
        signature: signatures,
        data_signature: (path, data_signatures?),
    }))
}

#[cfg(test)]
pub mod test {
    use crate::{
        event_message::cesr_adapter::EventType,
        event_parsing::parsers::{parse, parse_many},
    };

    #[test]
    fn test_signed_event() {
        use crate::event_message::cesr_adapter::EventType;
        // taken from KERIPY: tests/core/test_eventing.py::test_multisig_digprefix#2255
        let stream = br#"{"v":"KERI10JSON0001e7_","t":"icp","d":"EBfxc4RiVY6saIFmUfEtETs1FcqmktZW88UkbnOg0Qen","i":"EBfxc4RiVY6saIFmUfEtETs1FcqmktZW88UkbnOg0Qen","s":"0","kt":"2","k":["DErocgXD2RGSyvn3MObcx59jeOsEQhv2TqHirVkzrp0Q","DFXLiTjiRdSBPLL6hLa0rskIxk3dh4XwJLfctkJFLRSS","DE9YgIQVgpLwocTVrG8tidKScsQSMWwLWywNC48fhq4f"],"nt":"2","n":["EDJk5EEpC4-tQ7YDwBiKbpaZahh1QCyQOnZRF7p2i8k8","EAXfDjKvUFRj-IEB_o4y-Y_qeJAjYfZtOMD9e7vHNFss","EN8l6yJC2PxribTN0xfri6bLz34Qvj-x3cNwcV3DvT2m"],"bt":"0","b":[],"c":[],"a":[]}-AADAAD4SyJSYlsQG22MGXzRGz2PTMqpkgOyUfq7cS99sC2BCWwdVmEMKiTEeWe5kv-l_d9auxdadQuArLtAGEArW8wEABD0z_vQmFImZXfdR-0lclcpZFfkJJJNXDcUNrf7a-mGsxNLprJo-LROwDkH5m7tVrb-a1jcor2dHD9Jez-r4bQIACBFeU05ywfZycLdR0FxCvAR9BfV9im8tWe1DglezqJLf-vHRQSChY1KafbYNc96hYYpbuN90WzuCRMgV8KgRsEC"#;
        let parsed = parse::<EventType>(stream);
        assert!(parsed.is_ok());
        assert_eq!(parsed.unwrap().1.to_cesr().unwrap(), stream);
    }

    #[test]
    fn test_key_event_parsing() {
        // Inception event.
        let stream = br#"{"v":"KERI10JSON0000fd_","t":"icp","d":"EMW0zK3bagYPO6gx3w7Ua90f-I7x5kGIaI4Xeq9W8_As","i":"BFs8BBx86uytIM0D2BhsE5rrqVIT8ef8mflpNceHo4XH","s":"0","kt":"1","k":["BFs8BBx86uytIM0D2BhsE5rrqVIT8ef8mflpNceHo4XH"],"nt":"0","n":[],"bt":"0","b":[],"c":[],"a":[]}"#;
        let event = parse::<EventType>(stream);
        assert!(event.is_ok());
        assert_eq!(event.unwrap().1.to_cesr().unwrap(), stream);

        // Rotation event.
        let stream = br#"{"v":"KERI10JSON000160_","t":"rot","d":"EFl8nvRCbN2xQJI75nBXp-gaXuHJw8zheVjwMN_rB-pb","i":"DFs8BBx86uytIM0D2BhsE5rrqVIT8ef8mflpNceHo4XH","s":"1","p":"EJQUyxnzIAtmZPoq9f4fExeGN0qfJmaFnUEKTwIiTBPj","kt":"1","k":["DB4GWvru73jWZKpNgMQp8ayDRin0NG0Ymn_RXQP_v-PQ"],"nt":"1","n":["EIsKL3B6Zz5ICGxCQp-SoLXjwOrdlSbLJrEn21c2zVaU"],"bt":"0","br":[],"ba":[],"a":[]}"#;
        let event = parse::<EventType>(stream);
        assert!(event.is_ok());
        assert_eq!(event.unwrap().1.to_cesr().unwrap(), stream);

        // Interaction event without seals.
        let stream = br#"{"v":"KERI10JSON0000cb_","t":"ixn","d":"EKKccCumVQdgxvsrSXvuTtjmS28Xqf3zRJ8T6peKgl9J","i":"DFs8BBx86uytIM0D2BhsE5rrqVIT8ef8mflpNceHo4XH","s":"2","p":"ECauhEzA4DJDXVDnNQiGQ0sKXa6sx_GgS8Ebdzm4E-kQ","a":[]}"#;
        let event = parse::<EventType>(stream);
        assert!(event.is_ok());
        assert_eq!(event.unwrap().1.to_cesr().unwrap(), stream);

        // Interaction event with seal.
        let stream = br#"{"v":"KERI10JSON00013a_","t":"ixn","d":"EJtQndkvwnMpVGE5oVVbLWSCm-jLviGw1AOOkzBvNwsS","i":"EA_SbBUZYwqLVlAAn14d6QUBQCSReJlZ755JqTgmRhXH","s":"1","p":"EA_SbBUZYwqLVlAAn14d6QUBQCSReJlZ755JqTgmRhXH","a":[{"i":"EHng2fV42DdKb5TLMIs6bbjFkPNmIdQ5mSFn6BTnySJj","s":"0","d":"EHng2fV42DdKb5TLMIs6bbjFkPNmIdQ5mSFn6BTnySJj"}]}"#;
        let event = parse::<EventType>(stream);
        assert!(event.is_ok());
        assert_eq!(event.unwrap().1.to_cesr().unwrap(), stream);

        // Delegated inception event.
        let stream = br#"{"v":"KERI10JSON00015f_","t":"dip","d":"EN3PglLbr4mJblS4dyqbqlpUa735hVmLOhYUbUztxaiH","i":"EN3PglLbr4mJblS4dyqbqlpUa735hVmLOhYUbUztxaiH","s":"0","kt":"1","k":["DB4GWvru73jWZKpNgMQp8ayDRin0NG0Ymn_RXQP_v-PQ"],"nt":"1","n":["EIf-ENw7PrM52w4H-S7NGU2qVIfraXVIlV9hEAaMHg7W"],"bt":"0","b":[],"c":[],"a":[],"di":"EAdHxtdjCQUM-TVO8CgJAKb8ykXsFe4u9epTUQFCL7Yd"}"#;
        let event = parse::<EventType>(stream);
        assert_eq!(event.unwrap().1.to_cesr().unwrap(), stream);

        // Delegated rotation event.
        let stream = br#"{"v":"KERI10JSON000160_","t":"drt","d":"EMBBBkaLV7i6wNgfz3giib2ItrHsr548mtIflW0Hrbuv","i":"EN3PglLbr4mJblS4dyqbqlpUa735hVmLOhYUbUztxaiH","s":"4","p":"EANkcl_QewzrRSKH2p9zUskHI462CuIMS_HQIO132Z30","kt":"1","k":["DPLt4YqQsWZ5DPztI32mSyTJPRESONvE9KbETtCVYIeH"],"nt":"1","n":["EIsKL3B6Zz5ICGxCQp-SoLXjwOrdlSbLJrEn21c2zVaU"],"bt":"0","br":[],"ba":[],"a":[]}"#;
        let event = parse::<EventType>(stream);
        assert!(event.is_ok());
        assert_eq!(event.unwrap().1.to_cesr().unwrap(), stream);
    }

    #[test]
    fn test_receipt_parsing() {
        // Receipt event
        let stream = br#"{"v":"KERI10JSON000091_","t":"rct","d":"EKKccCumVQdgxvsrSXvuTtjmS28Xqf3zRJ8T6peKgl9J","i":"DFs8BBx86uytIM0D2BhsE5rrqVIT8ef8mflpNceHo4XH","s":"0"}"#;
        let event = parse::<EventType>(stream);
        assert!(event.is_ok());
        assert_eq!(event.unwrap().1.to_cesr().unwrap(), stream);
    }

    #[cfg(feature = "query")]
    #[test]
    fn test_qry() {
        // taken from keripy keripy/tests/core/test_eventing.py::test_messegize
        let qry_event = br#"{"v":"KERI10JSON0000c9_","t":"qry","d":"EGN68_seecuzXQO15FFGJLVwZCBCPYW-hy29fjWWPQbp","dt":"2021-01-01T00:00:00.000000+00:00","r":"log","rr":"","q":{"i":"DAvCLRr5luWmp7keDvDuLP0kIqcyBYq79b3Dho1QvrjI"}}"#;
        let rest = "something more".as_bytes();
        let stream = [qry_event, rest].concat();

        let (_extra, event) = parse::<EventType>(&stream).unwrap();
        assert!(matches!(event.payload, EventType::Qry(_)));
        assert_eq!(&event.to_cesr().unwrap(), qry_event);
    }

    #[test]
    fn test_exn() {
        let exn_event = br#"{"v":"KERI10JSON0002f1_","t":"exn","d":"EBLqTGJXK8ViUGXMOO8_LXbetpjJX8CY_SbA134RIZmf","dt":"2022-10-25T09:53:04.119676+00:00","r":"/fwd","q":{"pre":"EKYLUMmNPZeEs77Zvclf0bSN5IN-mLfLpx2ySb-HDlk4","topic":"multisig"},"a":{"v":"KERI10JSON000215_","t":"icp","d":"EC61gZ9lCKmHAS7U5ehUfEbGId5rcY0D7MirFZHDQcE2","i":"EC61gZ9lCKmHAS7U5ehUfEbGId5rcY0D7MirFZHDQcE2","s":"0","kt":"2","k":["DOZlWGPfDHLMf62zSFzE8thHmnQUOgA3_Y-KpOyF9ScG","DHGb2qY9WwZ1sBnC9Ip0F-M8QjTM27ftI-3jTGF9mc6K"],"nt":"2","n":["EBvD5VIVvf6NpP9GRmTqu_Cd1KN0RKrKNfPJ-uhIxurj","EHlpcaxffvtcpoUUMTc6tpqAVtb2qnOYVk_3HRsZ34PH"],"bt":"3","b":["BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha","BLskRTInXnMxWaGqcpSyMgo0nYbalW99cGZESrz3zapM","BIKKuvBwpmDVA4Ds-EpL5bt9OqPzWPja2LigFYZN2YfX"],"c":[],"a":[]}}-HABEJccSRTfXYF6wrUVuenAIHzwcx3hJugeiJsEKmndi5q1-AABAAArUSuSpts5zDQ7CgPcy305IxhAG8lOjf-r_d5yYQXp18OD9No_gd2McOOjGWMfjyLVjDK529pQcbvNv9Uwc6gH-LAZ5AABAA-a-AABAABYHc_lpuYF3SPNWvyPjzek7yquw69Csc6pLv5vrXHkFAFDcwNNTVxq7ZpxpqOO0CAIS-9Qj1zMor-cwvMHAmkE')"#;

        let (_extra, event) = parse::<EventType>(exn_event).unwrap();
        assert!(matches!(event.payload, EventType::Exn(_)));
    }

    #[cfg(feature = "query")]
    #[test]
    fn test_reply() {
        let rpy = br#"{"v":"KERI10JSON00029d_","t":"rpy","d":"EYFMuK9IQmHvq9KaJ1r67_MMCq5GnQEgLyN9YPamR3r0","dt":"2021-01-01T00:00:00.000000+00:00","r":"/ksn/E7YbTIkWWyNwOxZQTTnrs6qn8jFbu2A8zftQ33JYQFQ0","a":{"v":"KERI10JSON0001e2_","i":"E7YbTIkWWyNwOxZQTTnrs6qn8jFbu2A8zftQ33JYQFQ0","s":"3","p":"EF7f4gNFCbJz6ZHLacIi_bbIq7kaWAFOzX7ncU_vs5Qg","d":"EOPSPvHHVmU9IIdHa5ksisoVrOnmHRps_tx3OsZSQQ30","f":"3","dt":"2021-01-01T00:00:00.000000+00:00","et":"rot","kt":"1","k":["DrcAz_gmDTuWIHn_mOQDeSK_aJIRiw5IMzPD7igzEDb0"],"nt":"1","n":["EK7ZUmFebD2st48Yvtzc9LajV3Yg2mkeeDzVRL-7uKrU"],"bt":"0","b":[],"c":[],"ee":{"s":"3","d":"EOPSPvHHVmU9IIdHa5ksisoVrOnmHRps_tx3OsZSQQ30","br":[],"ba":[]},"di":""}}-VA0-FABE7YbTIkWWyNwOxZQTTnrs6qn8jFbu2A8zftQ33JYQFQ00AAAAAAAAAAAAAAAAAAAAAAwEOPSPvHHVmU9IIdHa5ksisoVrOnmHRps_tx3OsZSQQ30-AABAAYsqumzPM0bIo04gJ4Ln0zAOsGVnjHZrFjjjS49hGx_nQKbXuD1D4J_jNoEa4TPtPDnQ8d0YcJ4TIRJb-XouJBg"#;
        let rest = "something more".as_bytes();
        let stream = [rpy, rest].concat();

        let (_extra, event) = parse::<EventType>(&stream).unwrap();
        assert!(matches!(event.payload, EventType::Rpy(_)));
    }

    #[cfg(feature = "query")]
    #[test]
    fn test_signed_qry() {
        use nom::Needed;

        // Taken from keripy/tests/core/test_eventing.py::test_messagize (line 1471)
        let stream = br#"{"v":"KERI10JSON0000c9_","t":"qry","d":"E-WvgxrllmjGFhpn0oOiBkAVz3-dEm3bbiV_5qwj81xo","dt":"2021-01-01T00:00:00.000000+00:00","r":"log","rr":"","q":{"i":"DyvCLRr5luWmp7keDvDuLP0kIqcyBYq79b3Dho1QvrjI"}}-VAj-HABEZOIsLsfrVdBvULlg3Hg_Y1r-hadS82ZpglBLojPIQhg-AABAAuISeZIVO_wXjIrGJ-VcVMxr285OkKzAqVEQqVPFx8Ht2A9GQFB-zRA18J1lpqVphOnnXbTc51WR4uAvK90EHBg"#;
        let se = parse::<EventType>(&stream[..stream.len() - 1]);
        assert!(matches!(se, Err(nom::Err::Incomplete(Needed::Size(1)))));
        let se = parse::<EventType>(stream);
        assert!(se.is_ok());
    }

    #[test]
    fn test_signed_events_stream() {
        // Taken from keripy/tests/core/test_kevery.py::test kevery
        let kerl_str= br#"{"v":"KERI10JSON000120_","t":"icp","d":"EG4EuTsxPiRM7soX10XXzNsS1KqXKUp8xsQ-kW_tWHoI","i":"DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA","s":"0","kt":"1","k":["DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA"],"n":"EPYuj8mq_PYYsoBKkzX1kxSPGYBWaIya3slgCOyOtlqU","bt":"0","b":[],"c":[],"a":[]}-AABAA0aSisI4ZZTH_6JCqsvAsEpuf_Jq6bDbvPWj_eCDnAGbSARqYHipNs-9W7MHnwnMfIXwLpcoJkKGrQ-SiaklhAw{"v":"KERI10JSON000155_","t":"rot","d":"Ej30AgJV14mTTs427F3kILLrP_l03a27APg2FBO0-QtA","i":"DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA","s":"1","p":"EG4EuTsxPiRM7soX10XXzNsS1KqXKUp8xsQ-kW_tWHoI","kt":"1","k":["DVcuJOOJF1IE8svqEtrSuyQjGTd2HhfAkt9y2QkUtFJI"],"n":"E-dapdcC6XR1KWmWDsNl4J_OxcGxNZw1Xd95JH5a34fI","bt":"0","br":[],"ba":[],"a":[]}-AABAAwoiqt07w2UInzzo2DmtwkBfqX1-tTO4cYk_7YdlbJ95qA7PO5sEUkER8fZySQMNCVh64ruAh1yoew3TikwVGAQ{"v":"KERI10JSON000155_","t":"rot","d":"EmtXXRjyz6IdeX4201BgXKRDBm74gGqJF2r2umMMAL6I","i":"DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA","s":"2","p":"Ej30AgJV14mTTs427F3kILLrP_l03a27APg2FBO0-QtA","kt":"1","k":["DT1iAhBWCkvChxNWsby2J0pJyxBIxbAtbLA0Ljx-Grh8"],"n":"EKrLE2h2nh3ClyJNEjKaikHWT7G-ngimNpK-QgVQv9As","bt":"0","br":[],"ba":[],"a":[]}-AABAAW_RsDfAcHkknyzh9oeliH90KGPJEI8AP3rJPyuTnpVg8yOVtSIp_JFlyRwjV5SEQOqddAcRV6JtaQO8oXtWFCQ{"v":"KERI10JSON0000cb_","t":"ixn","d":"EY7E4RJXPe7FF1zQPbpSMIY-TYz9eAmNIhuprPYqTQ5o","i":"DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA","s":"3","p":"EmtXXRjyz6IdeX4201BgXKRDBm74gGqJF2r2umMMAL6I","a":[]}-AABAAlB0Ui5NHJpcifXUB6bAutmpZkhSgwxyI5jEZ2JGVBgTI02sC0Ugbq3q0EpOae7ruXW-eabUz2s0FAs26jGwVBg{"v":"KERI10JSON0000cb_","t":"ixn","d":"ENVzbZieVIjYLYkPWQy0gfua11KqdRG-oku5Ut8Dl6hU","i":"DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA","s":"4","p":"EY7E4RJXPe7FF1zQPbpSMIY-TYz9eAmNIhuprPYqTQ5o","a":[]}-AABAAWITFg460TXvYvxxzN62vpqpLs-vGgeGAbd-onY3DYxd5e3AljHh85pTum4Ha48F5dui9IVYqYvuYJCG8p8KvDw{"v":"KERI10JSON000155_","t":"rot","d":"E6wrLhilpPo4ePq7m7ZccEcKjwPD2q9mqzLUb_aO2Hi0","i":"DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA","s":"5","p":"ENVzbZieVIjYLYkPWQy0gfua11KqdRG-oku5Ut8Dl6hU","kt":"1","k":["DKPE5eeJRzkRTMOoRGVd2m18o8fLqM2j9kaxLhV3x8AQ"],"n":"EhVTfJFfl6L0Z0432mDUxeaqB_hlWPJ2qUuzG95gEyJU","bt":"0","br":[],"ba":[],"a":[]}-AABAAnqz-vnMx1cqe_SkcIrlx092UhbYzvvkHXjtxfuNDDcqnVtH11_8ZPaWomn3n963_bFTjjRhJaAH1SK8LU7s1DA{"v":"KERI10JSON0000cb_","t":"ixn","d":"Ek9gvRbkCt-wlgQBoV1PGm2iI__gaPURtJ3YrNFsXLzE","i":"DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA","s":"6","p":"E6wrLhilpPo4ePq7m7ZccEcKjwPD2q9mqzLUb_aO2Hi0","a":[]}-AABAAwGGWMNDpu8t4NuF_3M0jnkn3P063oUHmluwRwsyCg5tIvu-BfwIJRruAsCKry4LaI84dJAfAT5KJnG8xz9lJCw"#;
        let (rest, messages) = parse_many::<EventType>(kerl_str).unwrap();

        assert!(rest.is_empty());
        assert_eq!(messages.len(), 7);
    }
}
