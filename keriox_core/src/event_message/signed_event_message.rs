use cesrox::{group::Group, ParsedData};
use serde::{ser::SerializeStruct, Deserialize, Serialize};

use super::{
    key_event_message::KeyEvent, serializer::to_string, signature::Nontransferable, EventMessage,
};
#[cfg(feature = "query")]
use crate::query::{query_event::SignedQuery, reply_event::SignedReply};
use crate::{
    error::Error,
    event::{
        receipt::Receipt,
        sections::seal::{EventSeal, SourceSeal},
    },
    prefix::{AttachedSignaturePrefix, IdentifierPrefix},
    state::{EventSemantics, IdentifierState},
};

#[cfg(feature = "mailbox")]
use crate::mailbox::exchange::SignedExchange;

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
    #[cfg(feature = "mailbox")]
    Exchange(SignedExchange),
    #[cfg(any(feature = "query", feature = "oobi"))]
    Reply(SignedReply),
    #[cfg(feature = "query")]
    Query(SignedQuery),
}

impl From<Message> for ParsedData {
    fn from(message: Message) -> Self {
        match message {
            Message::Notice(notice) => ParsedData::from(notice),
            Message::Op(op) => ParsedData::from(op),
        }
    }
}

impl From<Notice> for ParsedData {
    fn from(notice: Notice) -> Self {
        match notice {
            Notice::Event(event) => ParsedData::from(&event),
            Notice::NontransferableRct(rct) => ParsedData::from(rct),
            Notice::TransferableRct(rct) => ParsedData::from(rct),
        }
    }
}

impl From<Op> for ParsedData {
    fn from(op: Op) -> Self {
        match op {
            #[cfg(feature = "query")]
            Op::Reply(ksn) => ParsedData::from(ksn),
            #[cfg(feature = "query")]
            Op::Query(qry) => ParsedData::from(qry),
            #[cfg(feature = "mailbox")]
            Op::Exchange(exn) => ParsedData::from(exn),
        }
    }
}

impl Message {
    pub fn to_cesr(&self) -> Result<Vec<u8>, Error> {
        ParsedData::from(self.clone())
            .to_cesr()
            .map_err(|_e| Error::CesrError)
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
            #[cfg(feature = "mailbox")]
            // returns exchange message receipient id
            Op::Exchange(exn) => exn.exchange_message.event.content.data.get_prefix(),
            _ => todo!(),
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
                            let signatures = indexed
                                .into_iter()
                                .map(|sig| (sig.clone()).into())
                                .collect();
                            Group::IndexedWitnessSignatures(signatures).to_cesr_str()
                        }
                        Nontransferable::Couplet(couplets) => {
                            let couples = couplets
                                .into_iter()
                                .map(|(bp, sp)| ((bp.clone()).into(), (sp.clone()).into()))
                                .collect();
                            Group::NontransReceiptCouples(couples).to_cesr_str()
                        }
                    })
                    .collect::<Vec<_>>()
                    .join("");
                em.serialize_field("", &att_receipts)?;
            }
            if let Some(ref seal) = self.delegator_seal {
                let att_seal =
                    Group::SourceSealCouples(vec![(seal.sn.into(), (&seal.digest).into())]);
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
        message: &EventMessage<KeyEvent>,
        sigs: Vec<AttachedSignaturePrefix>,
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
    // pub couplets: Option<Vec<(BasicPrefix, SelfSigningPrefix)>>,
    // pub indexed_sigs: Option<Vec<AttachedSignaturePrefix>>,
    pub signatures: Vec<Nontransferable>,
}

impl SignedNontransferableReceipt {
    pub fn new(message: &EventMessage<Receipt>, signatures: Vec<Nontransferable>) -> Self {
        Self {
            body: message.clone(),
            signatures,
        }
    }
}

#[cfg(test)]
pub mod tests {
    use std::convert::TryFrom;

    use cesrox::{parse, ParsedData};

    use crate::{
        actor::prelude::Message,
        error::Error,
        event_message::{
            signature::Nontransferable,
            signed_event_message::{Notice, Op},
        },
    };

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
        let parsed_witness_receipt: ParsedData = parse(witness_receipts).unwrap().1;

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

    #[ignore]
    #[test]
    fn test_deserialize_signed_exchange() -> Result<(), Error> {
        let exn_event = br#"{"v":"KERI10JSON0002f1_","t":"exn","d":"EBLqTGJXK8ViUGXMOO8_LXbetpjJX8CY_SbA134RIZmf","dt":"2022-10-25T09:53:04.119676+00:00","r":"/fwd","q":{"pre":"EKYLUMmNPZeEs77Zvclf0bSN5IN-mLfLpx2ySb-HDlk4","topic":"multisig"},"a":{"v":"KERI10JSON000215_","t":"icp","d":"EC61gZ9lCKmHAS7U5ehUfEbGId5rcY0D7MirFZHDQcE2","i":"EC61gZ9lCKmHAS7U5ehUfEbGId5rcY0D7MirFZHDQcE2","s":"0","kt":"2","k":["DOZlWGPfDHLMf62zSFzE8thHmnQUOgA3_Y-KpOyF9ScG","DHGb2qY9WwZ1sBnC9Ip0F-M8QjTM27ftI-3jTGF9mc6K"],"nt":"2","n":["EBvD5VIVvf6NpP9GRmTqu_Cd1KN0RKrKNfPJ-uhIxurj","EHlpcaxffvtcpoUUMTc6tpqAVtb2qnOYVk_3HRsZ34PH"],"bt":"3","b":["BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha","BLskRTInXnMxWaGqcpSyMgo0nYbalW99cGZESrz3zapM","BIKKuvBwpmDVA4Ds-EpL5bt9OqPzWPja2LigFYZN2YfX"],"c":[],"a":[]}}-HABEJccSRTfXYF6wrUVuenAIHzwcx3hJugeiJsEKmndi5q1-AABAAArUSuSpts5zDQ7CgPcy305IxhAG8lOjf-r_d5yYQXp18OD9No_gd2McOOjGWMfjyLVjDK529pQcbvNv9Uwc6gH-LAZ5AABAA-a-AABAABYHc_lpuYF3SPNWvyPjzek7yquw69Csc6pLv5vrXHkFAFDcwNNTVxq7ZpxpqOO0CAIS-9Qj1zMor-cwvMHAmkE"#;

        let parsed_exn = parse(exn_event).unwrap().1;
        let msg = Message::try_from(parsed_exn)?;
        assert!(matches!(msg, Message::Op(Op::Exchange(_))));
        assert_eq!(msg.to_cesr()?, exn_event);

        Ok(())
    }
}
