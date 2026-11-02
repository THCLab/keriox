use cesrox::group::{Group, SealSourceCouple};
use serde::{ser::SerializeStruct, Deserialize, Serialize};

use super::cesr_adapter::CesrMessage;
use super::{
    msg::KeriEvent, signature::Nontransferable,
};
use crate::prefix::cesr_adapter::receipt_couple;
#[cfg(feature = "query")]
use crate::query::{query_event::SignedQueryMessage, reply_event::SignedReply};
use crate::{
    error::Error,
    event::{
        receipt::Receipt,
        sections::seal::{EventSeal, SourceSeal},
        KeyEvent,
    },
    prefix::{IdentifierPrefix, IndexedSignature},
    state::{EventSemantics, IdentifierState},
};

#[cfg(feature = "exchange")]
use crate::exchange::SignedExchange;

#[derive(Clone, Debug, PartialEq)]
pub enum Message {
    Notice(Notice),
    #[cfg(feature = "query")]
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

#[cfg(any(feature = "query", feature = "oobi"))]
#[derive(Clone, Debug, PartialEq)]
pub enum Op {
    #[cfg(feature = "exchange")]
    Exchange(SignedExchange),
    #[cfg(feature = "query")]
    Reply(SignedReply),
    #[cfg(feature = "query")]
    Query(SignedQueryMessage),
}

impl From<Message> for CesrMessage {
    fn from(message: Message) -> Self {
        match message {
            Message::Notice(notice) => CesrMessage::from(notice),
            #[cfg(any(feature = "query", feature = "oobi"))]
            Message::Op(op) => CesrMessage::from(op),
        }
    }
}

impl From<Notice> for CesrMessage {
    fn from(notice: Notice) -> Self {
        match notice {
            Notice::Event(event) => CesrMessage::from(&event),
            Notice::NontransferableRct(rct) => CesrMessage::from(rct),
            Notice::TransferableRct(rct) => CesrMessage::from(rct),
        }
    }
}

#[cfg(feature = "query")]
impl From<Op> for CesrMessage {
    fn from(op: Op) -> Self {
        match op {
            #[cfg(feature = "query")]
            Op::Reply(ksn) => CesrMessage::from(ksn),
            #[cfg(feature = "query")]
            Op::Query(qry) => CesrMessage::from(qry),
            #[cfg(feature = "exchange")]
            Op::Exchange(exn) => CesrMessage::from(exn),
        }
    }
}

impl Message {
    /// The message with its attachments in CESR 2.0.
    pub fn to_cesr(&self) -> Result<Vec<u8>, Error> {
        CesrMessage::from(self.clone())
            .to_cesr()
            .map_err(|_e| Error::CesrError)
    }

    pub fn get_prefix(&self) -> IdentifierPrefix {
        match self {
            Message::Notice(notice) => notice.get_prefix(),
            #[cfg(any(feature = "query", feature = "oobi"))]
            Message::Op(op) => op.get_prefix(),
        }
    }
}

impl Notice {
    pub fn get_prefix(&self) -> IdentifierPrefix {
        match self {
            Notice::Event(ev) => ev.event_message.data.get_prefix(),
            Notice::NontransferableRct(rct) => rct.body.prefix.clone(),
            Notice::TransferableRct(rct) => rct.body.prefix.clone(),
        }
    }
}

#[cfg(feature = "query")]
impl Op {
    pub fn get_prefix(&self) -> IdentifierPrefix {
        match self {
            Op::Reply(reply) => reply.reply.get_prefix(),
            Op::Query(qry) => qry.prefix(),
            #[cfg(feature = "exchange")]
            // the exchange's recipient, ri
            Op::Exchange(exn) => exn.exchange_message.data.recipient.clone(),
        }
    }
}

// KERI serializer should be used to serialize this
#[derive(Debug, Clone, Deserialize)]
pub struct SignedEventMessage {
    pub event_message: KeriEvent<KeyEvent>,
    #[serde(skip_serializing)]
    pub signatures: Vec<IndexedSignature>,
    #[serde(skip_serializing)]
    pub witness_receipts: Option<Vec<Nontransferable>>,
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
            let mut em = serializer.serialize_struct("EventMessage", 4)?;
            em.serialize_field("", &self.event_message)?;
            let att_sigs = Group::IndexedControllerSignatures(
                self.signatures
                    .iter()
                    .map(|sig| sig.clone().into())
                    .collect(),
            );
            em.serialize_field("-", &att_sigs.to_cesr_str())?;
            if let Some(ref receipts) = self.witness_receipts {
                let att_receipts = receipts
                    .iter()
                    .map(|rct| match rct {
                        Nontransferable::Indexed(indexed) => {
                            let signatures =
                                indexed.iter().map(|sig| (sig.clone()).into()).collect();
                            Group::IndexedWitnessSignatures(signatures).to_cesr_str()
                        }
                        Nontransferable::Couplet(couplets) => {
                            let couples = couplets
                                .iter()
                                .map(|(bp, sp)| receipt_couple(bp.clone(), sp.clone()))
                                .collect();
                            Group::NontransReceiptCouples(couples).to_cesr_str()
                        }
                    })
                    .collect::<Vec<_>>()
                    .join("");
                em.serialize_field("", &att_receipts)?;
            }
            if let Some(ref seal) = self.delegator_seal {
                let att_seal = Group::SourceSealCouples(vec![SealSourceCouple::from(seal.clone())]);
                em.serialize_field("", &att_seal.to_cesr_str())?;
            }

            em.end()
        // . else - we pack as it is for DB / CBOR purpose
        } else {
            let mut em = serializer.serialize_struct("SignedEventMessage", 4)?;
            em.serialize_field("event_message", &self.event_message)?;
            em.serialize_field("signatures", &self.signatures)?;
            em.serialize_field("witness_receipts", &self.witness_receipts)?;
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

impl SignedEventMessage {
    pub fn new(
        message: &KeriEvent<KeyEvent>,
        sigs: Vec<IndexedSignature>,
        witness_receipts: Option<Vec<Nontransferable>>,
        delegator_seal: Option<SourceSeal>,
    ) -> Self {
        Self {
            event_message: message.clone(),
            signatures: sigs,
            witness_receipts,
            delegator_seal,
        }
    }

    /// The event with its attachments in CESR 2.0.
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        CesrMessage::from(self)
            .to_cesr()
            .map_err(|_e| Error::CesrError)
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
    pub body: Receipt,
    pub validator_seal: EventSeal,
    pub signatures: Vec<IndexedSignature>,
}

impl SignedTransferableReceipt {
    pub fn new(message: Receipt, event_seal: EventSeal, sigs: Vec<IndexedSignature>) -> Self {
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
    pub body: Receipt,
    // pub couplets: Option<Vec<(BasicPrefix, SelfSigningPrefix)>>,
    // pub indexed_sigs: Option<Vec<AttachedSignaturePrefix>>,
    pub signatures: Vec<Nontransferable>,
}

impl SignedNontransferableReceipt {
    pub fn new(message: &Receipt, signatures: Vec<Nontransferable>) -> Self {
        Self {
            body: message.clone(),
            signatures,
        }
    }
}

#[cfg(test)]
pub mod tests {
    use std::convert::TryFrom;

    use crate::{
        actor::prelude::Message,
        event_message::{signature::Nontransferable, signed_event_message::Notice},
    };

    use super::CesrMessage;

    #[test]
    fn test_stream1() {
        let stream = br#"-_AAACAA{"v":"KERI10JSON00012b_","t":"icp","d":"ECwI3rbyMMCCBrjBcZW-qIh4SFeY1ri6fl6nFNZ6_LPn","i":"DEzolW_U9CTatBFey9LL9e4_FOekoAJdTbReEstNEl-D","s":"0","kt":"1","k":["DEzolW_U9CTatBFey9LL9e4_FOekoAJdTbReEstNEl-D"],"nt":"1","n":["EL0nWR23_LnKW6OAXJauX2oz6N2V_QZfWeT4tsK-y3jZ"],"bt":"0","b":[],"c":[],"a":[]}-KAWAAB7Ro77feCA8A0B632ThEzVKGHwUrEx-TGyV8VdXKZvxPivaWqR__Exa7n02sjJkNlrQcOqs7cXsJ6IDopxkbEC"#;

        let parsed = CesrMessage::try_from(stream.as_ref()).unwrap();
        let msg = Message::try_from(parsed).unwrap();
        assert!(matches!(msg, Message::Notice(Notice::Event(_))));

        match msg {
            Message::Notice(Notice::Event(signed_event)) => {
                assert_eq!(
                    signed_event.event_message.encode().unwrap().len(),
                    signed_event.event_message.serialization_info.size
                );

                let serialized_again = signed_event.encode();
                assert!(serialized_again.is_ok());
                let stringified = String::from_utf8(serialized_again.unwrap()).unwrap();
                assert_eq!(stream, stringified.as_bytes());
            }
            _ => assert!(false),
        }
    }

    #[test]
    fn test_stream2() {
        let stream = br#"-_AAACAA{"v":"KERI10JSON0001e7_","t":"icp","d":"EBfxc4RiVY6saIFmUfEtETs1FcqmktZW88UkbnOg0Qen","i":"EBfxc4RiVY6saIFmUfEtETs1FcqmktZW88UkbnOg0Qen","s":"0","kt":"2","k":["DErocgXD2RGSyvn3MObcx59jeOsEQhv2TqHirVkzrp0Q","DFXLiTjiRdSBPLL6hLa0rskIxk3dh4XwJLfctkJFLRSS","DE9YgIQVgpLwocTVrG8tidKScsQSMWwLWywNC48fhq4f"],"nt":"2","n":["EDJk5EEpC4-tQ7YDwBiKbpaZahh1QCyQOnZRF7p2i8k8","EAXfDjKvUFRj-IEB_o4y-Y_qeJAjYfZtOMD9e7vHNFss","EN8l6yJC2PxribTN0xfri6bLz34Qvj-x3cNwcV3DvT2m"],"bt":"0","b":[],"c":[],"a":[]}-KBCAAD4SyJSYlsQG22MGXzRGz2PTMqpkgOyUfq7cS99sC2BCWwdVmEMKiTEeWe5kv-l_d9auxdadQuArLtAGEArW8wEABD0z_vQmFImZXfdR-0lclcpZFfkJJJNXDcUNrf7a-mGsxNLprJo-LROwDkH5m7tVrb-a1jcor2dHD9Jez-r4bQIACBFeU05ywfZycLdR0FxCvAR9BfV9im8tWe1DglezqJLf-vHRQSChY1KafbYNc96hYYpbuN90WzuCRMgV8KgRsEC"#;
        let parsed = CesrMessage::try_from(stream.as_ref()).unwrap();
        let msg = Message::try_from(parsed);
        assert!(msg.is_ok());
        assert!(matches!(msg, Ok(Message::Notice(Notice::Event(_)))));

        match msg.unwrap() {
            Message::Notice(Notice::Event(signed_event)) => {
                assert_eq!(
                    signed_event.event_message.encode().unwrap().len(),
                    signed_event.event_message.serialization_info.size
                );
                let serialized_again = signed_event.encode();
                assert!(serialized_again.is_ok());
                let stringified = String::from_utf8(serialized_again.unwrap()).unwrap();
                assert_eq!(stream, stringified.as_bytes())
            }
            _ => assert!(false),
        }
    }

    #[test]
    fn test_deserialize_signed_receipt() {
        let nontrans_rcp = br#"-_AAACAA{"v":"KERI10JSON000091_","t":"rct","d":"EL7aKmmdHtYKuJeBOYWRHbi8C6dYqzG-ESfdvlUAptlo","i":"EHz9RXAr9JiJn-3wkBvsUo1Qq3hvMQPaITxzcfJND8NM","s":"2"}-MAhBH89hKezugU2LFKiFVbitoHAxXqJh6HQ8Rn9tH7fxd680BBx_cu_UoMtD0ES-bS9Luh-b2A_AYmM3PmVNfgFrFXls4IE39-_D14dS46NEMqCf0vQmqDcQmhY-UOpgoyFS2Bw"#;
        let parsed_nontrans_receipt = CesrMessage::try_from(nontrans_rcp.as_ref()).unwrap();
        let msg = Message::try_from(parsed_nontrans_receipt);
        assert!(msg.is_ok());
        assert!(matches!(
            msg,
            Ok(Message::Notice(Notice::NontransferableRct(_)))
        ));

        let witness_receipts = br#"-_AAACAA{"v":"KERI10JSON000091_","t":"rct","d":"EHz9RXAr9JiJn-3wkBvsUo1Qq3hvMQPaITxzcfJND8NM","i":"EHz9RXAr9JiJn-3wkBvsUo1Qq3hvMQPaITxzcfJND8NM","s":"0"}-LBCAABgQkf11JTyF2WVA1Vji1ZhXD8di4AJsfro-sN_jURM1SUioeOleik7w8lkDldKtg0-Nr1X32V9Q8tk8RvBGxDgABBmkRun-qNliRA8WR2fIUnVeB8eFLF7aLFtn2hb31iW7wYSYafR0kT3fV_r1wNNdjm9dkBw-_2xsxThTGfO5UAwACBGJiRPFe4ClvpqZL3LHcEAeT396WVrYV10EaTdt0trINT8rPbz96deSFT32z3myNPVwLlNcq4FzIaQCooM2HDQ"#;
        let parsed_witness_receipt = CesrMessage::try_from(witness_receipts.as_ref()).unwrap();

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

    #[cfg(feature = "exchange")]
    #[test]
    fn test_deserialize_signed_exchange() {
        use crate::event_message::signed_event_message::Op;
        let exn_event = br#"{"v":"KERICAACAAJSONAAGJ.","t":"exn","d":"EJ7fardNHewIxRFQxO0QrzawpYRHh3jhfTjQ2FuAmC8E","i":"EJ_XPdN9hbhbblm5JuU3y45viXKOTZqbMxD3hEggp0pD","ri":"EJ_XPdN9hbhbblm5JuU3y45viXKOTZqbMxD3hEggp0pD","x":"","p":"","dt":"2024-01-01T00:00:00.000000+00:00","r":"/fwd","q":{"pre":"EJ_XPdN9hbhbblm5JuU3y45viXKOTZqbMxD3hEggp0pD","topic":"multisig"},"a":{"evt":"EML-lfYS2KNY1hGN5nzjUbBTBkOHqKw6MbNEyJFMPHgn"}}-CCt-XAuEJ_XPdN9hbhbblm5JuU3y45viXKOTZqbMxD3hEggp0pDMAAAEJ_XPdN9hbhbblm5JuU3y45viXKOTZqbMxD3hEggp0pD-KAWAACYHV0RI_0YMPa7JwhDHMtcVlSj8UonfXMQ_EFFjoMVJEQXa5r2bJoMPl7VjeRtJXmvTI_4i9XTcMdVVhaZu0IN-BB9-HBl5BBkAHsidiI6IktFUkkxMEpTT04wMDAxMmJfIiwidCI6ImljcCIsImQiOiJFSl9YUGROOWhiaGJibG01SnVVM3k0NXZpWEtPVFpxYk14RDNoRWdncDBwRCIsImkiOiJFSl9YUGROOWhiaGJibG01SnVVM3k0NXZpWEtPVFpxYk14RDNoRWdncDBwRCIsInMiOiIwIiwia3QiOiIxIiwiayI6WyJERWJiR01KMFVyWlBCYlpDZ2pVSFB2bEJLUEtWLXMwa3NPWklSb0ZGOGNnNSJdLCJudCI6IjEiLCJuIjpbIkVGVk9RMEZILTRnSldvYnlXYVdla2R2eTh2VXlNVEtIYUEzZ0ZZbkJYdDBRIl0sImJ0IjoiMCIsImIiOltdLCJjIjpbXSwiYSI6W119-KAWAACj84Cf9s2C6cTNd4Rv5bSWbj4fJRdOgg82yf0A_PkUTMjNYUc40-3HxMNx3fhsDEhsKR1Br1YWhtI-pfgS-oIE"#;

        let parsed_exn = CesrMessage::try_from(exn_event.as_ref()).unwrap();
        let msg = Message::try_from(parsed_exn).unwrap();
        assert!(matches!(msg, Message::Op(Op::Exchange(_))));
        // Verify round-trip serialization produces valid CESR (may use different counter codes)
        let serialized = msg.to_cesr().unwrap();
        let reparsed = CesrMessage::try_from(serialized.as_slice()).unwrap();
        let msg2 = Message::try_from(reparsed).unwrap();
        assert!(matches!(msg2, Message::Op(Op::Exchange(_))));
    }
}
