use std::convert::{TryFrom, TryInto};

use serde::Deserialize;

use crate::{
    error::Error,
    event::{
        event_data::EventData,
        receipt::Receipt,
        sections::seal::{EventSeal, SourceSeal},
    },
    event_parsing::{
        error::Error as CesrError, group::Group, message::version, parsers::parse,
        primitives::IndexedSignature, ParsedData, Payload,
    },
    query::{
        query_event::{QueryEvent, SignedQuery},
        reply_event::{ReplyEvent, SignedReply},
    },
};

use super::{
    exchange::{ExchangeMessage, SignedExchange},
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

    fn get_len(stream: &[u8]) -> Result<usize, CesrError> {
        // TODO works only for json. How to find version string?
        let version_str = &stream.get(5..24).ok_or(CesrError::EmptyStreamError)?;
        let (_, version) = version(version_str).unwrap();
        Ok(version.size)
    }
}

#[derive(Clone, Debug, PartialEq, Deserialize)]
#[serde(untagged)]
pub enum EventType {
    KeyEvent(EventMessage<KeyEvent>),
    Receipt(EventMessage<Receipt>),
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
            EventType::Exn(exn) => signed_exchange(exn, value.attachments),
            _ => Err(Error::SemanticError(
                "Cannot convert SignedEventData to Op".to_string(),
            )),
        }
    }
}

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

pub fn signed_exchange(exn: ExchangeMessage, attachments: Vec<Group>) -> Result<Op, Error> {
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

#[test]
fn test_stream1() {
    // taken from KERIPY: tests/core/test_kevery.py#62
    let stream = br#"{"v":"KERI10JSON00012b_","t":"icp","d":"ECwI3rbyMMCCBrjBcZW-qIh4SFeY1ri6fl6nFNZ6_LPn","i":"DEzolW_U9CTatBFey9LL9e4_FOekoAJdTbReEstNEl-D","s":"0","kt":"1","k":["DEzolW_U9CTatBFey9LL9e4_FOekoAJdTbReEstNEl-D"],"nt":"1","n":["EL0nWR23_LnKW6OAXJauX2oz6N2V_QZfWeT4tsK-y3jZ"],"bt":"0","b":[],"c":[],"a":[]}-AABAAB7Ro77feCA8A0B632ThEzVKGHwUrEx-TGyV8VdXKZvxPivaWqR__Exa7n02sjJkNlrQcOqs7cXsJ6IDopxkbEC"#;

    let parsed = parse(stream).unwrap().1;
    let msg = Message::try_from(parsed).unwrap();
    assert!(matches!(msg, Message::Notice(Notice::Event(_))));

    match msg {
        Message::Notice(Notice::Event(signed_event)) => {
            assert_eq!(
                signed_event.event_message.serialize().unwrap().len(),
                signed_event.event_message.serialization_info.size
            );

            let serialized_again = signed_event.serialize();
            assert!(serialized_again.is_ok());
            let stringified = String::from_utf8(serialized_again.unwrap()).unwrap();
            assert_eq!(stream, stringified.as_bytes());
        }
        _ => assert!(false),
    }
}

#[test]
fn test_stream2() {
    // taken from KERIPY: tests/core/test_eventing.py::test_multisig_digprefix#2256
    let stream = br#"{"v":"KERI10JSON0001e7_","t":"icp","d":"EBfxc4RiVY6saIFmUfEtETs1FcqmktZW88UkbnOg0Qen","i":"EBfxc4RiVY6saIFmUfEtETs1FcqmktZW88UkbnOg0Qen","s":"0","kt":"2","k":["DErocgXD2RGSyvn3MObcx59jeOsEQhv2TqHirVkzrp0Q","DFXLiTjiRdSBPLL6hLa0rskIxk3dh4XwJLfctkJFLRSS","DE9YgIQVgpLwocTVrG8tidKScsQSMWwLWywNC48fhq4f"],"nt":"2","n":["EDJk5EEpC4-tQ7YDwBiKbpaZahh1QCyQOnZRF7p2i8k8","EAXfDjKvUFRj-IEB_o4y-Y_qeJAjYfZtOMD9e7vHNFss","EN8l6yJC2PxribTN0xfri6bLz34Qvj-x3cNwcV3DvT2m"],"bt":"0","b":[],"c":[],"a":[]}-AADAAD4SyJSYlsQG22MGXzRGz2PTMqpkgOyUfq7cS99sC2BCWwdVmEMKiTEeWe5kv-l_d9auxdadQuArLtAGEArW8wEABD0z_vQmFImZXfdR-0lclcpZFfkJJJNXDcUNrf7a-mGsxNLprJo-LROwDkH5m7tVrb-a1jcor2dHD9Jez-r4bQIACBFeU05ywfZycLdR0FxCvAR9BfV9im8tWe1DglezqJLf-vHRQSChY1KafbYNc96hYYpbuN90WzuCRMgV8KgRsEC"#;
    let parsed = parse(stream).unwrap().1;
    let msg = Message::try_from(parsed);
    assert!(msg.is_ok());
    assert!(matches!(msg, Ok(Message::Notice(Notice::Event(_)))));

    match msg.unwrap() {
        Message::Notice(Notice::Event(signed_event)) => {
            assert_eq!(
                signed_event.event_message.serialize().unwrap().len(),
                signed_event.event_message.serialization_info.size
            );
            let serialized_again = signed_event.serialize();
            assert!(serialized_again.is_ok());
            let stringified = String::from_utf8(serialized_again.unwrap()).unwrap();
            assert_eq!(stream, stringified.as_bytes())
        }
        _ => assert!(false),
    }
}

#[test]
fn test_deserialize_signed_receipt() {
    // Taken from keripy/tests/core/test_eventing.py::test_direct_mode
    let trans_receipt_event = br#"{"v":"KERI10JSON000091_","t":"rct","d":"EsZuhYAPBDnexP3SOl9YsGvWBrYkjYcRjomUYmCcLAYY","i":"EsZuhYAPBDnexP3SOl9YsGvWBrYkjYcRjomUYmCcLAYY","s":"0"}-FABE7pB5IKuaYh3aIWKxtexyYFhpSjDNTEGSQuxeJbWiylg0AAAAAAAAAAAAAAAAAAAAAAAE7pB5IKuaYh3aIWKxtexyYFhpSjDNTEGSQuxeJbWiylg-AABAAlIts3z2kNyis9l0Pfu54HhVN_yZHEV7NWIVoSTzl5IABelbY8xi7VRyW42ZJvBaaFTGtiqwMOywloVNpG_ZHAQ"#;
    let parsed_trans_receipt = parse(trans_receipt_event).unwrap().1;
    let msg = Message::try_from(parsed_trans_receipt);
    assert!(matches!(
        msg,
        Ok(Message::Notice(Notice::TransferableRct(_)))
    ));
    assert!(msg.is_ok());

    // Taken from keripy/core/test_witness.py::test_nonindexed_witness_receipts
    let nontrans_rcp = br#"{"v":"KERI10JSON000091_","t":"rct","d":"E77aKmmdHtYKuJeBOYWRHbi8C6dYqzG-ESfdvlUAptlo","i":"EHz9RXAr9JiJn-3wkBvsUo1Qq3hvMQPaITxzcfJND8NM","s":"2"}-CABB389hKezugU2LFKiFVbitoHAxXqJh6HQ8Rn9tH7fxd680Bpx_cu_UoMtD0ES-bS9Luh-b2A_AYmM3PmVNfgFrFXls4IE39-_D14dS46NEMqCf0vQmqDcQmhY-UOpgoyFS2Bw"#;
    let parsed_nontrans_receipt = parse(nontrans_rcp).unwrap().1;
    let msg = Message::try_from(parsed_nontrans_receipt);
    assert!(msg.is_ok());
    assert!(matches!(
        msg,
        Ok(Message::Notice(Notice::NontransferableRct(_)))
    ));

    // takien from keripy/tests/core/test_witness.py::test_indexed_witness_reply
    let witness_receipts = br#"{"v":"KERI10JSON000091_","t":"rct","d":"EHz9RXAr9JiJn-3wkBvsUo1Qq3hvMQPaITxzcfJND8NM","i":"EHz9RXAr9JiJn-3wkBvsUo1Qq3hvMQPaITxzcfJND8NM","s":"0"}-BADAAdgQkf11JTyF2WVA1Vji1ZhXD8di4AJsfro-sN_jURM1SUioeOleik7w8lkDldKtg0-Nr1X32V9Q8tk8RvBGxDgABZmkRun-qNliRA8WR2fIUnVeB8eFLF7aLFtn2hb31iW7wYSYafR0kT3fV_r1wNNdjm9dkBw-_2xsxThTGfO5UAwACRGJiRPFe4ClvpqZL3LHcEAeT396WVrYV10EaTdt0trINT8rPbz96deSFT32z3myNPVwLlNcq4FzIaQCooM2HDQ"#;
    let parsed_witness_receipt: ParsedEvent = parse(witness_receipts).unwrap().1;

    let msg = Message::try_from(parsed_witness_receipt);
    assert!(msg.is_ok());
    if let Ok(Message::Notice(Notice::NontransferableRct(rct))) = msg {
        match &rct.signatures[0] {
            Nontransferable::Indexed(indexed) => {
                assert_eq!(3, indexed.len());
            }
            Nontransferable::Couplet(_) => {
                unreachable!()
            }
        };
    } else {
        assert!(false)
    };
}

#[test]
fn test_deserialize_signed_exchange() -> Result<(), Error> {
    let exn_event = br#"{"v":"KERI10JSON0002f1_","t":"exn","d":"EBLqTGJXK8ViUGXMOO8_LXbetpjJX8CY_SbA134RIZmf","dt":"2022-10-25T09:53:04.119676+00:00","r":"/fwd","q":{"pre":"EKYLUMmNPZeEs77Zvclf0bSN5IN-mLfLpx2ySb-HDlk4","topic":"multisig"},"a":{"v":"KERI10JSON000215_","t":"icp","d":"EC61gZ9lCKmHAS7U5ehUfEbGId5rcY0D7MirFZHDQcE2","i":"EC61gZ9lCKmHAS7U5ehUfEbGId5rcY0D7MirFZHDQcE2","s":"0","kt":"2","k":["DOZlWGPfDHLMf62zSFzE8thHmnQUOgA3_Y-KpOyF9ScG","DHGb2qY9WwZ1sBnC9Ip0F-M8QjTM27ftI-3jTGF9mc6K"],"nt":"2","n":["EBvD5VIVvf6NpP9GRmTqu_Cd1KN0RKrKNfPJ-uhIxurj","EHlpcaxffvtcpoUUMTc6tpqAVtb2qnOYVk_3HRsZ34PH"],"bt":"3","b":["BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha","BLskRTInXnMxWaGqcpSyMgo0nYbalW99cGZESrz3zapM","BIKKuvBwpmDVA4Ds-EpL5bt9OqPzWPja2LigFYZN2YfX"],"c":[],"a":[]}}-HABEJccSRTfXYF6wrUVuenAIHzwcx3hJugeiJsEKmndi5q1-AABAAArUSuSpts5zDQ7CgPcy305IxhAG8lOjf-r_d5yYQXp18OD9No_gd2McOOjGWMfjyLVjDK529pQcbvNv9Uwc6gH-LAZ5AABAA-a-AABAABYHc_lpuYF3SPNWvyPjzek7yquw69Csc6pLv5vrXHkFAFDcwNNTVxq7ZpxpqOO0CAIS-9Qj1zMor-cwvMHAmkE"#;

    let parsed_exn = parse(exn_event).unwrap().1;
    let msg = Message::try_from(parsed_exn)?;
    assert!(matches!(msg, Message::Op(Op::Exchange(_))));
    assert_eq!(msg.to_cesr()?, exn_event);

    Ok(())
}
