//! The KERI specification defines the exchange (`exn`) as a KERI 2.0
//! message that names its sender `i`, its recipient `ri`, its transaction
//! `x` and the prior message `p` before `dt`. The sender must have signed
//! it, and a forward goes to the mailbox of the recipient it names.
#![cfg(feature = "exchange")]

use std::sync::Arc;

use keri_core::{
    actor::{event_generator, parse_op_stream, process_notice, verify_forward},
    database::redb::RedbDatabase,
    event::{sections::seal::EventSeal, KeyEvent},
    event_message::{
        event_msg_builder::EventMsgBuilder,
        keri_version::KeriVersion,
        msg::KeriEvent,
        signature::{Signature, SignerData},
        signed_event_message::{Message, Notice, Op},
        EventTypeTag,
    },
    error::Error,
    exchange::{ExchangeMessage, ForwardTopic, SignedExchange},
    prefix::{BasicPrefix, IdentifierPrefix, IndexedSignature, SelfSigningPrefix},
    processor::{basic_processor::BasicProcessor, event_storage::EventStorage},
    signer::Signer,
};
use said::{
    derivation::{HashFunction, HashFunctionCode},
    version::format::SerializationFormats,
};
use tempfile::NamedTempFile;

struct Fixture {
    _path: NamedTempFile,
    processor: BasicProcessor<RedbDatabase>,
    storage: EventStorage<RedbDatabase>,
}

fn setup() -> Fixture {
    let path = NamedTempFile::new().unwrap();
    let db = Arc::new(RedbDatabase::new(path.path()).unwrap());
    Fixture {
        _path: path,
        processor: BasicProcessor::new(db.clone(), None),
        storage: EventStorage::new(db),
    }
}

/// An identifier the node knows, incepted in KERI 2.0.
fn known(fx: &Fixture, signer: &Signer) -> KeriEvent<KeyEvent> {
    let icp = EventMsgBuilder::new(EventTypeTag::Icp)
        .with_version(KeriVersion::V2_0)
        .with_keys(vec![BasicPrefix::Ed25519(signer.public_key())])
        .with_next_keys(vec![BasicPrefix::Ed25519(Signer::new().public_key())])
        .build()
        .unwrap();
    let sig = SelfSigningPrefix::Ed25519Sha512(signer.sign(icp.encode().unwrap()).unwrap());
    process_notice(
        Notice::Event(icp.sign(vec![IndexedSignature::new_both_same(sig, 0)], None, None)),
        &fx.processor,
    )
    .unwrap();
    icp
}

fn seal_of(icp: &KeriEvent<KeyEvent>) -> EventSeal {
    EventSeal::new(icp.data.get_prefix(), 0, icp.digest().unwrap())
}

/// `exn` signed by `signer` under the key state of `signer_icp`, carrying
/// `forwarded`, signed by `signer` as well, nested.
fn signed(
    exn: ExchangeMessage,
    signer: &Signer,
    signer_icp: &KeriEvent<KeyEvent>,
    forwarded: &KeriEvent<KeyEvent>,
) -> SignedExchange {
    let sig = |data: &[u8]| {
        vec![IndexedSignature::new_both_same(
            SelfSigningPrefix::Ed25519Sha512(signer.sign(data).unwrap()),
            0,
        )]
    };
    let exn_signature = vec![Signature::Transferable(
        SignerData::EventSeal(seal_of(signer_icp)),
        sig(&exn.encode().unwrap()),
    )];
    let forwarded = forwarded.sign(sig(&forwarded.encode().unwrap()), None, None);
    SignedExchange::forward(exn, exn_signature, Message::Notice(Notice::Event(forwarded)))
}

/// `exn`, signed as by [`signed`], read back from the wire.
fn through_the_wire(
    exn: ExchangeMessage,
    signer: &Signer,
    signer_icp: &KeriEvent<KeyEvent>,
    forwarded: &KeriEvent<KeyEvent>,
) -> Result<SignedExchange, String> {
    let signed = signed(exn, signer, signer_icp, forwarded);
    let cesr = Message::Op(Op::Exchange(signed)).to_cesr().unwrap();
    match parse_op_stream(&cesr).map_err(|e| e.to_string())?.remove(0) {
        Op::Exchange(exn) => Ok(exn),
        other => panic!("not an exchange: {other:?}"),
    }
}

/// The position of the top-level field `name` in a JSON body.
fn field(raw: &str, name: &str) -> usize {
    raw.find(&format!(r#""{name}":"#)).unwrap()
}

#[test]
fn an_exchange_names_its_sender_and_recipient() {
    let fx = setup();
    let signer = Signer::new();
    let icp = known(&fx, &signer);
    let sender = icp.data.get_prefix();
    let recipient = IdentifierPrefix::Basic(BasicPrefix::Ed25519NT(Signer::new().public_key()));
    let exn = event_generator::exchange(&sender, &recipient, &icp, ForwardTopic::Multisig);
    let raw = String::from_utf8(exn.encode().unwrap()).unwrap();
    assert!(raw.starts_with(r#"{"v":"KERICAACAAJSON"#), "{raw}");
    let order = ["d", "i", "ri", "x", "p", "dt", "r", "q", "a"].map(|name| field(&raw, name));
    assert!(order.windows(2).all(|pair| pair[0] < pair[1]), "{raw}");
    assert!(raw.contains(&format!(
        r#""i":"{sender}","ri":"{recipient}","x":"","p":"""#
    )));

    let signed = through_the_wire(exn, &signer, &icp, &icp).unwrap();
    verify_forward(&signed, &fx.storage).unwrap();
}

/// A forward names the forwarded body's digest in `a.evt` and carries the
/// message nested in its attachments, in an attachment group, so it is read
/// as one message. The recipient takes the forwarded event with its
/// signatures.
#[test]
fn a_forward_carries_the_forwarded_message_nested() {
    let fx = setup();
    let signer = Signer::new();
    let icp = known(&fx, &signer);
    let recipient = IdentifierPrefix::Basic(BasicPrefix::Ed25519NT(Signer::new().public_key()));
    let exn = event_generator::exchange(
        &icp.data.get_prefix(),
        &recipient,
        &icp,
        ForwardTopic::Multisig,
    );
    let raw = String::from_utf8(exn.encode().unwrap()).unwrap();
    let evt = HashFunction::from(HashFunctionCode::Blake3_256).derive(&icp.encode().unwrap());
    assert!(raw.contains(&format!(r#""a":{{"evt":"{evt}"}}"#)), "{raw}");

    let cesr = Message::Op(Op::Exchange(signed(exn.clone(), &signer, &icp, &icp)))
        .to_cesr()
        .unwrap();
    let after_body = &cesr[exn.encode().unwrap().len()..];
    assert!(after_body.starts_with(b"-C"), "{}", String::from_utf8_lossy(after_body));
    let ops = parse_op_stream(&cesr).unwrap();
    assert_eq!(ops.len(), 1);
    let Op::Exchange(read) = &ops[0] else {
        panic!("not an exchange")
    };
    let [Message::Notice(Notice::Event(forwarded))] = read.nested.as_slice() else {
        panic!("no forwarded event: {:?}", read.nested)
    };
    assert_eq!(forwarded.event_message, icp);

    let taken = verify_forward(read, &fx.storage).unwrap();
    assert_eq!(taken.recipient, recipient);
    assert_eq!(taken.topic, ForwardTopic::Multisig);
    assert_eq!(taken.event.event_message, icp);
    assert_eq!(taken.event.signatures, forwarded.signatures);
}

/// A forward without the message `a.evt` names, or with another one, is
/// refused when read.
#[test]
fn a_forward_without_the_named_message_is_refused() {
    let fx = setup();
    let signer = Signer::new();
    let icp = known(&fx, &signer);
    let other = known(&fx, &Signer::new());
    let recipient = IdentifierPrefix::Basic(BasicPrefix::Ed25519NT(Signer::new().public_key()));
    let exn = event_generator::exchange(
        &icp.data.get_prefix(),
        &recipient,
        &icp,
        ForwardTopic::Multisig,
    );
    let refused = through_the_wire(exn.clone(), &signer, &icp, &other).unwrap_err();
    assert!(refused.contains("a.evt"), "{refused}");

    let mut bare = signed(exn, &signer, &icp, &icp);
    bare.nested.clear();
    let cesr = Message::Op(Op::Exchange(bare)).to_cesr().unwrap();
    assert!(parse_op_stream(&cesr).is_err());
}

#[test]
fn an_exchange_signed_by_someone_else_is_refused() {
    let fx = setup();
    let (sender_signer, other_signer) = (Signer::new(), Signer::new());
    let sender_icp = known(&fx, &sender_signer);
    let other_icp = known(&fx, &other_signer);
    let exn = event_generator::exchange(
        &sender_icp.data.get_prefix(),
        &other_icp.data.get_prefix(),
        &sender_icp,
        ForwardTopic::Multisig,
    );
    assert!(through_the_wire(exn.clone(), &other_signer, &other_icp, &sender_icp).is_err());
    // Nor is it taken when handed over without the parser.
    let forged = signed(exn, &other_signer, &other_icp, &sender_icp);
    assert!(matches!(
        verify_forward(&forged, &fx.storage),
        Err(Error::SemanticError(_))
    ));
}

/// The forward goes to the mailbox of the AID in `q.pre`; an exchange
/// naming another recipient in `ri` contradicts itself.
#[test]
fn a_forward_for_another_recipient_than_ri_is_refused() {
    let fx = setup();
    let signer = Signer::new();
    let icp = known(&fx, &signer);
    let mut exn = event_generator::exchange(
        &icp.data.get_prefix(),
        &IdentifierPrefix::Basic(BasicPrefix::Ed25519NT(Signer::new().public_key())),
        &icp,
        ForwardTopic::Multisig,
    );
    exn.data.recipient =
        IdentifierPrefix::Basic(BasicPrefix::Ed25519NT(Signer::new().public_key()));
    let exn = KeriEvent::new(
        KeriVersion::V2_0,
        SerializationFormats::JSON,
        HashFunctionCode::Blake3_256.into(),
        exn.data,
    );
    let exn = through_the_wire(exn, &signer, &icp, &icp).unwrap();
    assert!(matches!(
        verify_forward(&exn, &fx.storage),
        Err(Error::SemanticError(_))
    ));
}

/// The specification defines no KERI 1.0 exchange.
#[test]
fn a_keri_1_exchange_is_refused() {
    let fx = setup();
    let signer = Signer::new();
    let icp = known(&fx, &signer);
    let exn = event_generator::exchange(
        &icp.data.get_prefix(),
        &icp.data.get_prefix(),
        &icp,
        ForwardTopic::Multisig,
    );
    let keri1 = KeriEvent::new(
        KeriVersion::V1_0,
        SerializationFormats::JSON,
        HashFunctionCode::Blake3_256.into(),
        exn.data,
    );
    let raw = String::from_utf8(keri1.encode().unwrap()).unwrap();
    assert!(raw.starts_with(r#"{"v":"KERI10JSON"#), "{raw}");
    let refused = through_the_wire(keri1, &signer, &icp, &icp).unwrap_err();
    assert!(refused.contains("KERI 2.0"), "{refused}");
}

/// A forward keripy 424a50c writes in KERI 2.0 (the sender's inception, then
/// an exn naming that inception by the digest of its body and carrying it
/// nested), as `keri.app.forwarding` builds it.
const KERIPY_FORWARD: &str = r#"{"v":"KERICAACAAJSONAAEt.","t":"icp","d":"EIm3qJsC-Zt9LWiJGd_V7KSHXyK2-coPiPjOiAs0rlxJ","i":"EIm3qJsC-Zt9LWiJGd_V7KSHXyK2-coPiPjOiAs0rlxJ","s":"0","kt":"1","k":["DOR1qM4x1Y8fjsgzsAGUNrs4xoB4Nq8pnYExz5Zlob9b"],"nt":"1","n":["EGKHGuVFL8IphnkFXqTD5KFdrbqqiixdjMrMgwbvX--b"],"bt":"0","b":[],"c":[],"a":[]}-CAX-KAWAABzlQkKHQlWu8Kqk8kkyaKTLtCmSVHbYkzCPJuI4_04cqVDd7TBaEk4m91mQ-D0oaYBocUe7G_Vw8MivAVdwVgI{"v":"KERICAACAAJSONAAGJ.","t":"exn","d":"EME5P9wRSi2xyIzcjy0uOOaALIe2eI0VmhHnTM9p9sM2","i":"EIm3qJsC-Zt9LWiJGd_V7KSHXyK2-coPiPjOiAs0rlxJ","ri":"EO8m6PSESVVeddChKbExqvrllOeiy5B2gMgcMHS6p_UD","x":"","p":"","dt":"2026-10-27T23:14:25.908929+00:00","r":"/fwd","q":{"pre":"EO8m6PSESVVeddChKbExqvrllOeiy5B2gMgcMHS6p_UD","topic":"multisig"},"a":{"evt":"EA2Wr3knDvyelcSyySV-5qrLSdZ7O8rlnit3hZqtmm0y"}}-CCu-XAuEIm3qJsC-Zt9LWiJGd_V7KSHXyK2-coPiPjOiAs0rlxJMAAAEIm3qJsC-Zt9LWiJGd_V7KSHXyK2-coPiPjOiAs0rlxJ-KAWAABV1RfKXsh8q0eiHNmChrI5ZjvEXHmhQabaYJoIhN5CbLq5QY996QUscUL2xFy51AvLajKcbS7x1nx_5T0sJVML-BB--HBm6BBlAAB7InYiOiJLRVJJQ0FBQ0FBSlNPTkFBRXQuIiwidCI6ImljcCIsImQiOiJFSW0zcUpzQy1adDlMV2lKR2RfVjdLU0hYeUsyLWNvUGlQak9pQXMwcmx4SiIsImkiOiJFSW0zcUpzQy1adDlMV2lKR2RfVjdLU0hYeUsyLWNvUGlQak9pQXMwcmx4SiIsInMiOiIwIiwia3QiOiIxIiwiayI6WyJET1IxcU00eDFZOGZqc2d6c0FHVU5yczR4b0I0TnE4cG5ZRXh6NVpsb2I5YiJdLCJudCI6IjEiLCJuIjpbIkVHS0hHdVZGTDhJcGhua0ZYcVRENUtGZHJicXFpaXhkak1yTWd3YnZYLS1iIl0sImJ0IjoiMCIsImIiOltdLCJjIjpbXSwiYSI6W119-KAWAABzlQkKHQlWu8Kqk8kkyaKTLtCmSVHbYkzCPJuI4_04cqVDd7TBaEk4m91mQ-D0oaYBocUe7G_Vw8MivAVdwVgI"#;

/// keriox reads keripy's forward and takes the forwarded inception, as
/// keripy's own mailbox does with keriox's.
#[test]
fn a_forward_written_by_keripy_is_read_and_taken() {
    let fx = setup();
    let messages: Vec<Message> =
        keri_core::event_message::cesr_adapter::parse_cesr_stream_many(KERIPY_FORWARD.as_bytes())
            .unwrap()
            .into_iter()
            .map(|message| Message::try_from(message).unwrap())
            .collect();
    let [Message::Notice(icp), Message::Op(Op::Exchange(exn))] = messages.as_slice() else {
        panic!("not an inception and a forward: {messages:?}")
    };
    process_notice(icp.clone(), &fx.processor).unwrap();
    let [Message::Notice(Notice::Event(forwarded))] = exn.nested.as_slice() else {
        panic!("no forwarded event: {:?}", exn.nested)
    };
    let recipient = exn.exchange_message.data.recipient.clone();
    let taken = verify_forward(exn, &fx.storage).unwrap();
    assert_eq!(taken.recipient, recipient);
    assert_eq!(taken.event.event_message, forwarded.event_message);
    // Written again, keriox's encoding of it is keripy's.
    assert_eq!(
        String::from_utf8(Message::Op(Op::Exchange(exn.clone())).to_cesr().unwrap()).unwrap(),
        KERIPY_FORWARD[KERIPY_FORWARD.find(r#"{"v":"KERICAACAAJSONAAGJ.","t":"exn""#).unwrap()..]
    );
}

