use std::convert::{TryFrom, TryInto};

use base64::URL_SAFE_NO_PAD;
use chrono::{DateTime, FixedOffset, SecondsFormat};
use serde::Deserialize;

use self::path::MaterialPath;
#[cfg(feature = "query")]
use crate::query::{
    query_event::{QueryEvent, SignedQuery},
    reply_event::{ReplyEvent, SignedReply},
};
use crate::{
    error::Error,
    event::{
        event_data::EventData,
        receipt::Receipt,
        sections::seal::{EventSeal, SourceSeal},
        EventMessage,
    },
    event_message::{
        exchange::{ExchangeMessage, SignedExchange},
        key_event_message::KeyEvent,
        signature::{self, Nontransferable, Signature},
        signed_event_message::{
            Message, Notice, Op, SignedEventMessage, SignedNontransferableReceipt,
            SignedTransferableReceipt,
        },
    },
    event_parsing::payload_size::PayloadType,
    prefix::{AttachedSignaturePrefix, BasicPrefix, IdentifierPrefix, Prefix, SelfSigningPrefix},
};

pub mod attachment;
pub mod message;
pub mod parsing;
pub mod path;
pub mod payload_size;
pub mod prefix;

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub enum Attachment {
    // Count codes
    SealSourceCouplets(Vec<SourceSeal>),
    AttachedSignatures(Vec<AttachedSignaturePrefix>),
    AttachedWitnessSignatures(Vec<AttachedSignaturePrefix>),
    ReceiptCouplets(Vec<(BasicPrefix, SelfSigningPrefix)>),
    // Count of attached qualified Base64 first seen replay couples fn+dt
    FirstSeenReply(Vec<(u64, DateTime<FixedOffset>)>),
    // Group codes
    SealSignaturesGroups(Vec<(EventSeal, Vec<AttachedSignaturePrefix>)>),
    PathedMaterialQuadruplet(MaterialPath, Vec<Signature>),
    // List of signatures made using keys from last establishment event od identifier of prefix
    LastEstSignaturesGroups(Vec<(IdentifierPrefix, Vec<AttachedSignaturePrefix>)>),
    // Frame codes
    Frame(Vec<Attachment>),
}

impl Attachment {
    pub fn to_cesr(&self) -> String {
        let (payload_type, att_len, serialized_attachment) = match self {
            Attachment::SealSourceCouplets(sources) => {
                let serialzied_sources = sources.iter().fold("".into(), |acc, s| {
                    [acc, Self::pack_sn(s.sn), s.digest.to_str()].join("")
                });

                (PayloadType::MG, sources.len(), serialzied_sources)
            }
            Attachment::SealSignaturesGroups(seals_signatures) => {
                let serialized_seals =
                    seals_signatures
                        .iter()
                        .fold("".into(), |acc, (seal, sigs)| {
                            [
                                acc,
                                seal.prefix.to_str(),
                                Self::pack_sn(seal.sn),
                                seal.event_digest.to_str(),
                                Attachment::AttachedSignatures(sigs.to_vec()).to_cesr(),
                            ]
                            .join("")
                        });
                (PayloadType::MF, seals_signatures.len(), serialized_seals)
            }
            Attachment::AttachedSignatures(sigs) => {
                let serialized_sigs = sigs
                    .iter()
                    .fold("".into(), |acc, sig| [acc, sig.to_str()].join(""));
                (PayloadType::MA, sigs.len(), serialized_sigs)
            }
            Attachment::AttachedWitnessSignatures(sigs) => {
                let serialized_sigs = sigs
                    .iter()
                    .fold("".into(), |acc, sig| [acc, sig.to_str()].join(""));
                (PayloadType::MB, sigs.len(), serialized_sigs)
            }
            Attachment::ReceiptCouplets(couplets) => {
                let packed_couplets = couplets.iter().fold("".into(), |acc, (bp, sp)| {
                    [acc, bp.to_str(), sp.to_str()].join("")
                });

                (PayloadType::MC, couplets.len(), packed_couplets)
            }
            Attachment::LastEstSignaturesGroups(signers) => {
                let packed_signers = signers.iter().fold("".to_string(), |acc, (signer, sigs)| {
                    [
                        acc,
                        signer.to_str(),
                        Attachment::AttachedSignatures(sigs.clone()).to_cesr(),
                    ]
                    .concat()
                });
                (PayloadType::MH, signers.len(), packed_signers)
            }
            Attachment::Frame(att) => {
                let packed_attachments = att
                    .iter()
                    .fold("".to_string(), |acc, att| [acc, att.to_cesr()].concat());
                (
                    PayloadType::MV,
                    packed_attachments.len(),
                    packed_attachments,
                )
            }
            Attachment::FirstSeenReply(couplets) => {
                let packed_couplets =
                    couplets.iter().fold("".into(), |acc, (first_seen_sn, dt)| {
                        [
                            acc,
                            first_seen_sn.to_string(),
                            dt.to_rfc3339_opts(SecondsFormat::Micros, false),
                        ]
                        .join("")
                    });

                (PayloadType::ME, couplets.len(), packed_couplets)
            }
            Attachment::PathedMaterialQuadruplet(path, signatures) => {
                let attachments = path.to_cesr()
                    + &signature::signatures_into_attachments(&signatures)
                        .iter()
                        .map(|s| s.to_cesr())
                        .fold(String::new(), |a, b| a + &b);
                (PayloadType::ML, attachments.len() / 4, attachments)
            }
        };
        [
            payload_type.adjust_with_num(att_len as u16),
            serialized_attachment,
        ]
        .join("")
    }

    fn pack_sn(sn: u64) -> String {
        let payload_type = PayloadType::OA;
        let sn_raw: Vec<u8> = sn.to_be_bytes().into();
        // Calculate how many zeros are missing to achieve expected base64 string
        // length. Master code size is expected padding size.
        let missing_zeros =
            payload_type.size() / 4 * 3 - payload_type.master_code_size(false) - sn_raw.len();
        let sn_vec: Vec<u8> = std::iter::repeat(0)
            .take(missing_zeros)
            .chain(sn_raw)
            .collect();
        [
            payload_type.to_string(),
            base64::encode_config(sn_vec, URL_SAFE_NO_PAD),
        ]
        .join("")
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct SignedEventData {
    pub deserialized_event: EventType,
    pub attachments: Vec<Attachment>,
}

#[derive(Clone, Debug, PartialEq)]
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

impl SignedEventData {
    pub fn to_cesr(&self) -> Result<Vec<u8>, Error> {
        let attachments = self
            .attachments
            .iter()
            .fold(String::default(), |acc, att| [acc, att.to_cesr()].concat())
            .as_bytes()
            .to_vec();
        Ok([self.deserialized_event.serialize()?, attachments].concat())
    }
}

impl From<&SignedEventMessage> for SignedEventData {
    fn from(ev: &SignedEventMessage) -> Self {
        let mut attachments: Vec<_> = match ev.delegator_seal.clone() {
            Some(delegator_seal) => [
                Attachment::SealSourceCouplets(vec![delegator_seal]),
                Attachment::AttachedSignatures(ev.signatures.clone()),
            ]
            .into(),
            None => [Attachment::AttachedSignatures(ev.signatures.clone())].into(),
        };

        if let Some(witness_rcts) = &ev.witness_receipts {
            witness_rcts.iter().for_each(|rcts| match rcts {
                Nontransferable::Indexed(indexed) => {
                    attachments.push(Attachment::AttachedWitnessSignatures(indexed.clone()))
                }
                Nontransferable::Couplet(couplets) => {
                    attachments.push(Attachment::ReceiptCouplets(couplets.clone()))
                }
            });
        };

        SignedEventData {
            deserialized_event: EventType::KeyEvent(ev.event_message.clone()),
            attachments,
        }
    }
}

impl From<SignedNontransferableReceipt> for SignedEventData {
    fn from(rcp: SignedNontransferableReceipt) -> SignedEventData {
        let attachments = rcp
            .signatures
            .iter()
            .map(|sig| match sig {
                Nontransferable::Indexed(indexed) => {
                    Attachment::AttachedWitnessSignatures(indexed.clone())
                }
                Nontransferable::Couplet(couplets) => Attachment::ReceiptCouplets(couplets.clone()),
            })
            .collect();
        SignedEventData {
            deserialized_event: EventType::Receipt(rcp.body),
            attachments,
        }
    }
}

impl From<SignedTransferableReceipt> for SignedEventData {
    fn from(rcp: SignedTransferableReceipt) -> SignedEventData {
        let attachments = [Attachment::SealSignaturesGroups(vec![(
            rcp.validator_seal,
            rcp.signatures,
        )])]
        .into();
        SignedEventData {
            deserialized_event: EventType::Receipt(rcp.body),
            attachments,
        }
    }
}

#[cfg(feature = "query")]
impl From<SignedReply> for SignedEventData {
    fn from(ev: SignedReply) -> Self {
        let attachments = vec![(&ev.signature).into()];
        SignedEventData {
            deserialized_event: EventType::Rpy(ev.reply),
            attachments,
        }
    }
}

#[cfg(feature = "query")]
impl From<SignedQuery> for SignedEventData {
    fn from(ev: SignedQuery) -> Self {
        let attachments = vec![Attachment::LastEstSignaturesGroups(vec![(
            ev.signer,
            ev.signatures,
        )])];

        SignedEventData {
            deserialized_event: EventType::Qry(ev.query),
            attachments,
        }
    }
}

impl From<SignedExchange> for SignedEventData {
    fn from(ev: SignedExchange) -> Self {
        let mut attachments = signature::signatures_into_attachments(&ev.signature);
        let data_attachment =
            Attachment::PathedMaterialQuadruplet(ev.data_signature.0, ev.data_signature.1);
        attachments.push(data_attachment);
        SignedEventData {
            deserialized_event: EventType::Exn(ev.exchange_message),
            attachments,
        }
    }
}

impl TryFrom<SignedEventData> for Message {
    type Error = Error;

    fn try_from(value: SignedEventData) -> Result<Self, Self::Error> {
        let msg = match value.deserialized_event {
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

impl TryFrom<SignedEventData> for Notice {
    type Error = Error;

    fn try_from(value: SignedEventData) -> Result<Self, Self::Error> {
        match Message::try_from(value)? {
            Message::Notice(notice) => Ok(notice),
            _ => Err(Error::SemanticError(
                "Cannot convert SignedEventData to Notice".to_string(),
            )),
        }
    }
}

impl TryFrom<SignedEventData> for Op {
    type Error = Error;

    fn try_from(value: SignedEventData) -> Result<Self, Self::Error> {
        match value.deserialized_event {
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

impl TryFrom<SignedEventData> for SignedQuery {
    type Error = Error;

    fn try_from(value: SignedEventData) -> Result<Self, Self::Error> {
        match Op::try_from(value)? {
            Op::Query(qry) => Ok(qry),
            _ => Err(Error::SemanticError(
                "Cannot convert SignedEventData to SignedQuery".to_string(),
            )),
        }
    }
}

impl TryFrom<SignedEventData> for SignedReply {
    type Error = Error;

    fn try_from(value: SignedEventData) -> Result<Self, Self::Error> {
        match Op::try_from(value)? {
            Op::Reply(rpy) => Ok(rpy),
            _ => Err(Error::SemanticError(
                "Cannot convert SignedEventData to SignedReply".to_string(),
            )),
        }
    }
}

impl TryFrom<SignedEventData> for SignedExchange {
    type Error = Error;

    fn try_from(value: SignedEventData) -> Result<Self, Self::Error> {
        match Op::try_from(value)? {
            Op::Exchange(exn) => Ok(exn),
            _ => Err(Error::SemanticError(
                "Cannot convert SignedEventData to SignedExchange".to_string(),
            )),
        }
    }
}

#[cfg(any(feature = "query", feature = "oobi"))]
fn signed_reply(rpy: ReplyEvent, mut attachments: Vec<Attachment>) -> Result<Op, Error> {
    match attachments
        .pop()
        .ok_or_else(|| Error::SemanticError("Missing attachment".into()))?
    {
        Attachment::ReceiptCouplets(couplets) => {
            let signer = couplets[0].0.clone();
            let signature = couplets[0].1.clone();
            Ok(Op::Reply(SignedReply::new_nontrans(rpy, signer, signature)))
        }
        Attachment::SealSignaturesGroups(data) => {
            let (seal, sigs) = data
                // TODO what if more than one?
                .last()
                .ok_or_else(|| Error::SemanticError("More than one seal".into()))?
                .to_owned();
            Ok(Op::Reply(SignedReply::new_trans(rpy, seal, sigs)))
        }
        Attachment::Frame(atts) => signed_reply(rpy, atts),
        _ => {
            // Improper payload type
            Err(Error::SemanticError("Improper payload type".into()))
        }
    }
}

#[cfg(feature = "query")]
fn signed_query(qry: QueryEvent, mut attachments: Vec<Attachment>) -> Result<Op, Error> {
    match attachments
        .pop()
        .ok_or_else(|| Error::SemanticError("Missing attachment".into()))?
    {
        Attachment::LastEstSignaturesGroups(groups) => {
            let (signer, signatures) = groups[0].clone();
            Ok(Op::Query(SignedQuery {
                query: qry,
                signer,
                signatures,
            }))
        }
        Attachment::Frame(atts) => signed_query(qry, atts),
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
    mut attachments: Vec<Attachment>,
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
                    Attachment::SealSourceCouplets(seals),
                    Some(Attachment::AttachedSignatures(sigs)),
                ) => Ok((Some(seals), sigs)),
                (
                    Attachment::AttachedSignatures(sigs),
                    Some(Attachment::SealSourceCouplets(seals)),
                ) => Ok((Some(seals), sigs)),
                (Attachment::AttachedSignatures(sigs), None) => Ok((None, sigs)),
                _ => {
                    // Improper attachment type
                    Err(Error::SemanticError("Improper attachment type".into()))
                }
            }?;

            let delegator_seal = if let Some(seal) = seals {
                match seal.len() {
                    0 => Err(Error::SemanticError("Missing delegator seal".into())),
                    1 => Ok(seal.first().cloned()),
                    _ => Err(Error::SemanticError("Too many seals".into())),
                }
            } else {
                Ok(None)
            };

            Ok(Notice::Event(SignedEventMessage::new(
                &event_message,
                sigs,
                None,
                delegator_seal?,
            )))
        }
        _ => {
            let signatures = if let Attachment::Frame(atts) = attachments
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
                    if let Attachment::AttachedSignatures(sigs) = att {
                        Some(sigs)
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
                    Attachment::AttachedWitnessSignatures(indexed) => {
                        Some(Nontransferable::Indexed(indexed))
                    }
                    Attachment::ReceiptCouplets(couplets) => {
                        Some(Nontransferable::Couplet(couplets))
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
    mut attachments: Vec<Attachment>,
) -> Result<Notice, Error> {
    let nontransferable = attachments
        .iter()
        .filter_map(|att| match att {
            Attachment::AttachedWitnessSignatures(sigs) => {
                Some(Nontransferable::Indexed(sigs.clone()))
            }
            Attachment::ReceiptCouplets(couplts) => Some(Nontransferable::Couplet(couplts.clone())),
            _ => None,
        })
        .collect();
    let att = attachments
        .pop()
        .ok_or_else(|| Error::SemanticError("Missing attachment".into()))?;

    match att {
        // Should be nontransferable receipt
        Attachment::ReceiptCouplets(_) | Attachment::AttachedWitnessSignatures(_) => {
            Ok(Notice::NontransferableRct(SignedNontransferableReceipt {
                body: event_message,
                signatures: nontransferable,
            }))
        }
        Attachment::SealSignaturesGroups(data) => {
            // Should be transferable receipt
            let (seal, sigs) = data
                // TODO what if more than one?
                .last()
                .ok_or_else(|| Error::SemanticError("More than one seal".into()))?
                .to_owned();
            Ok(Notice::TransferableRct(SignedTransferableReceipt::new(
                event_message,
                seal,
                sigs,
            )))
        }
        Attachment::Frame(atts) => signed_receipt(event_message, atts),
        _ => {
            // Improper payload type
            Err(Error::SemanticError("Improper payload type".into()))
        }
    }
}

pub fn signed_exchange(exn: ExchangeMessage, attachments: Vec<Attachment>) -> Result<Op, Error> {
    let mut atts = attachments.into_iter();
    let att1 = atts
        .next()
        .ok_or_else(|| Error::SemanticError("Missing attachment".into()))?;
    let att2 = atts
        .next()
        .ok_or_else(|| Error::SemanticError("Missing attachment".into()))?;

    let (path, data_sigs, signatures): (_, _, Vec<Signature>) = match (att1, att2) {
        (Attachment::PathedMaterialQuadruplet(path, sigs), anything)
        | (anything, Attachment::PathedMaterialQuadruplet(path, sigs)) => {
            (path, sigs, anything.try_into()?)
        }
        _ => return Err(Error::SemanticError("Wrong attachment".into())),
    };

    Ok(Op::Exchange(SignedExchange {
        exchange_message: exn,
        signature: signatures,
        data_signature: (path, data_sigs),
    }))
}

#[test]
fn test_stream1() {
    use crate::event_parsing;
    // taken from KERIPY: tests/core/test_kevery.py#62
    let stream = br#"{"v":"KERI10JSON00012b_","t":"icp","d":"ELeMG3OOxWi5n1Zud603_Bn6Hzm3hIRZXlQnSgC5lU7A","i":"DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA","s":"0","kt":"1","k":["DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA"],"nt":"1","n":["E67B6WkwQrEfSA2MylxmF28HJc_HxfHRyK1kRXSYeMiI"],"bt":"0","b":[],"c":[],"a":[]}-AABAAw6czYydWCMpfs-XpUPi-h2OuBHP6ji5IU7YbK0pnsQt237sI4jaALv7Guc30y1zh8j5hrou-zOoUrVINlhSICw"#;

    let parsed = event_parsing::message::signed_message(stream).unwrap().1;
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
    use crate::event_parsing;
    // taken from KERIPY: tests/core/test_eventing.py::test_multisig_digprefix#2256
    let stream = br#"{"v":"KERI10JSON0001e7_","t":"icp","d":"EZrJQSdhdiyXNpEzHo-dR0EEbLfcIopBSImdLnQGOKkg","i":"EZrJQSdhdiyXNpEzHo-dR0EEbLfcIopBSImdLnQGOKkg","s":"0","kt":"2","k":["DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA","DVcuJOOJF1IE8svqEtrSuyQjGTd2HhfAkt9y2QkUtFJI","DT1iAhBWCkvChxNWsby2J0pJyxBIxbAtbLA0Ljx-Grh8"],"nt":"2","n":["E_IkdcjsIFrFba-LS1sJDjpec_4vM3XtIPa6D51GcUIw","EU28GjHFKeXzncPxgwlHQZ0iO7f09Y89vy-3VkZ23bBI","E2PRzip7UZ5UTA_1ucb5eoAzxeRS3sIThrSbZhdRaZY8"],"bt":"0","b":[],"c":[],"a":[]}-AADAAzclB26m4VWp5R8ANlTU2qhqE6GA9siAK_vhtqtNNR6qhVed-xEoXRadnL5Jc0kxPZi8XUqSk5KSaOnke_SxXDAABX--x4JGI0Dp0Ran-t1LMg3NEgizu1Jb85LTImofYqD6jz9w5TTPNAmj7rfIFvd4mfJ_ioH0Z0mzLWuIvTIFCBAACQTiHacY3flY9y_Wup66bNzcyQvJUT-WGkv4CPgqkMwq5mOEFf2ps74bur1AE9OSGgrEBlcOQ9HWuTcr80FMKCg"#;

    let parsed = event_parsing::message::signed_message(stream).unwrap().1;
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
    use crate::event_parsing::message::signed_message;
    // Taken from keripy/tests/core/test_eventing.py::test_direct_mode
    let trans_receipt_event = br#"{"v":"KERI10JSON000091_","t":"rct","d":"EsZuhYAPBDnexP3SOl9YsGvWBrYkjYcRjomUYmCcLAYY","i":"EsZuhYAPBDnexP3SOl9YsGvWBrYkjYcRjomUYmCcLAYY","s":"0"}-FABE7pB5IKuaYh3aIWKxtexyYFhpSjDNTEGSQuxeJbWiylg0AAAAAAAAAAAAAAAAAAAAAAAE7pB5IKuaYh3aIWKxtexyYFhpSjDNTEGSQuxeJbWiylg-AABAAlIts3z2kNyis9l0Pfu54HhVN_yZHEV7NWIVoSTzl5IABelbY8xi7VRyW42ZJvBaaFTGtiqwMOywloVNpG_ZHAQ"#;
    let parsed_trans_receipt = signed_message(trans_receipt_event).unwrap().1;
    let msg = Message::try_from(parsed_trans_receipt);
    assert!(matches!(
        msg,
        Ok(Message::Notice(Notice::TransferableRct(_)))
    ));
    assert!(msg.is_ok());

    // Taken from keripy/core/test_witness.py::test_nonindexed_witness_receipts
    let nontrans_rcp = br#"{"v":"KERI10JSON000091_","t":"rct","d":"E77aKmmdHtYKuJeBOYWRHbi8C6dYqzG-ESfdvlUAptlo","i":"EHz9RXAr9JiJn-3wkBvsUo1Qq3hvMQPaITxzcfJND8NM","s":"2"}-CABB389hKezugU2LFKiFVbitoHAxXqJh6HQ8Rn9tH7fxd680Bpx_cu_UoMtD0ES-bS9Luh-b2A_AYmM3PmVNfgFrFXls4IE39-_D14dS46NEMqCf0vQmqDcQmhY-UOpgoyFS2Bw"#;
    let parsed_nontrans_receipt = signed_message(nontrans_rcp).unwrap().1;
    let msg = Message::try_from(parsed_nontrans_receipt);
    assert!(msg.is_ok());
    assert!(matches!(
        msg,
        Ok(Message::Notice(Notice::NontransferableRct(_)))
    ));

    // Nontrans receipt with alternative attachment with -B payload type. Not implemented yet.
    // takien from keripy/tests/core/test_witness.py::test_indexed_witness_reply
    let witness_receipts = r#"{"v":"KERI10JSON000091_","t":"rct","d":"EHz9RXAr9JiJn-3wkBvsUo1Qq3hvMQPaITxzcfJND8NM","i":"EHz9RXAr9JiJn-3wkBvsUo1Qq3hvMQPaITxzcfJND8NM","s":"0"}-BADAAdgQkf11JTyF2WVA1Vji1ZhXD8di4AJsfro-sN_jURM1SUioeOleik7w8lkDldKtg0-Nr1X32V9Q8tk8RvBGxDgABZmkRun-qNliRA8WR2fIUnVeB8eFLF7aLFtn2hb31iW7wYSYafR0kT3fV_r1wNNdjm9dkBw-_2xsxThTGfO5UAwACRGJiRPFe4ClvpqZL3LHcEAeT396WVrYV10EaTdt0trINT8rPbz96deSFT32z3myNPVwLlNcq4FzIaQCooM2HDQ"#;
    let parsed_witness_receipt = signed_message(witness_receipts.as_bytes()).unwrap();
    assert!(parsed_witness_receipt.0.is_empty());

    let msg = Message::try_from(parsed_witness_receipt.1);
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
    use crate::event_parsing::message::signed_message;

    let exn_event = r#"{"v":"KERI10JSON0002c9_","t":"exn","d":"Eru6l4p3-r6KJkT1Ac8r5XWuQMsD91-c80hC7lASOoZI","r":"/fwd","q":{"pre":"E-4-PsMBN0YEKyTl3zL0zulWcBehdaaG6Go5cMc0BzQ8","topic":"multisig"},"a":{"v":"KERI10JSON000215_","t":"icp","d":"EOWwyMU3XA7RtWdelFt-6waurOTH_aW_Z9VTaU-CshGk","i":"EOWwyMU3XA7RtWdelFt-6waurOTH_aW_Z9VTaU-CshGk","s":"0","kt":"2","k":["DQKeRX-2dXdSWS-EiwYyiQdeIwesvubEqnUYC5vsEyjo","D-U6Sc6VqQC3rDuD2wLF3oR8C4xQyWOTMp4zbJyEnRlE"],"nt":"2","n":["ENVtv0_G68psQhfWB-ZyVH1lndLli2LSmfSxxszNufoI","E6UpCouA9mZA03hMFJLrhA0SvwR4HVNqf2wrZM-ydTSI"],"bt":"3","b":["BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo","BuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw","Bgoq68HCmYNUDgOz4Skvlu306o_NY-NrYuKAVhk3Zh9c"],"c":[],"a":[]}}-HABEozYHef4je02EkMOA1IKM65WkIdSjfrL7XWDk_JzJL9o-AABAArQYXZsfglDLnZrGGYUyhNzriWJTSuKjqRrcrDik3zch94IQ9tjQwz0K0iikVCENApxSSo9tBQT7pz9d9G1O0DQ-LAZ5AABAA-a-AABAAFjjD99-xy7J0LGmCkSE_zYceED5uPF4q7l8J23nNQ64U-oWWulHI5dh3cFDWT4eICuEQCALdh8BO5ps-qx0qBA"#;

    let parsed_trans_receipt = signed_message(exn_event.as_bytes()).unwrap().1;
    let msg = Message::try_from(parsed_trans_receipt)?;
    assert!(matches!(msg, Message::Op(Op::Exchange(_))));
    assert_eq!(String::from_utf8(msg.to_cesr()?).unwrap(), exn_event);

    Ok(())
}
