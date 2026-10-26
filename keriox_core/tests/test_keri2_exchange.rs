//! The KERI specification defines the exchange (`exn`) as a KERI 2.0
//! message that names its sender `i`, its recipient `ri`, its transaction
//! `x` and the prior message `p` before `dt`. The sender must have signed
//! it, and a forward goes to the mailbox of the recipient it names.
#![cfg(feature = "mailbox")]

use std::sync::Arc;

use keri_core::{
    actor::{event_generator, parse_op_stream, process_notice, process_signed_exn, MaterialPath},
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
    mailbox::exchange::{ExchangeMessage, ForwardTopic, SignedExchange},
    prefix::{BasicPrefix, IdentifierPrefix, IndexedSignature, SelfSigningPrefix},
    processor::{basic_processor::BasicProcessor, event_storage::EventStorage},
    signer::Signer,
};
use said::{derivation::HashFunctionCode, version::format::SerializationFormats};
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
        storage: EventStorage::new_redb(db),
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
/// `forwarded` signed by its own controller.
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
    SignedExchange {
        signature: vec![Signature::Transferable(
            SignerData::EventSeal(seal_of(signer_icp)),
            sig(&exn.encode().unwrap()),
        )],
        data_signature: (
            MaterialPath::create_from_str("-a".into()).unwrap(),
            vec![Signature::Transferable(
                SignerData::EventSeal(seal_of(signer_icp)),
                sig(&forwarded.encode().unwrap()),
            )],
        ),
        exchange_message: exn,
    }
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
    process_signed_exn(signed, &fx.storage).unwrap();
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
        process_signed_exn(forged, &fx.storage),
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
        process_signed_exn(exn, &fx.storage),
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
