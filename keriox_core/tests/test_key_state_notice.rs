//! A key state notice (`/ksn` reply) carries an identifier's key state.
//! Its sequence numbers are hex like every KERI sequence number, its `et`
//! names the last event type, and its `ee` describes the last establishment
//! event: that event's sn and SAID and the witnesses it removed (`br`) and
//! added (`ba`).
#![cfg(feature = "query")]

use std::sync::Arc;

use keri_core::event_message::keri_version::KeriVersion;
use keri_core::{
    actor::{parse_reply_stream, process_notice},
    database::redb::RedbDatabase,
    event::{sections::threshold::SignatureThreshold, KeyEvent},
    event_message::{
        event_msg_builder::EventMsgBuilder,
        msg::KeriEvent,
        signed_event_message::{Message, Notice, Op},
        EventTypeTag,
    },
    prefix::{BasicPrefix, CesrPrimitive, IdentifierPrefix, IndexedSignature, SelfSigningPrefix},
    processor::{basic_processor::BasicProcessor, event_storage::EventStorage},
    query::{
        key_state_notice::KeyStateNotice,
        reply_event::{ReplyEvent, ReplyRoute, SignedReply},
    },
    signer::Signer,
};
use said::{derivation::HashFunctionCode, version::format::SerializationFormats};
use serde_json::{json, Value};
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

fn key(signer: &Signer) -> BasicPrefix {
    BasicPrefix::Ed25519(signer.public_key())
}

fn process(fx: &Fixture, event: &KeriEvent<KeyEvent>, signer: &Signer) {
    let sig = SelfSigningPrefix::Ed25519Sha512(signer.sign(event.encode().unwrap()).unwrap());
    process_notice(
        Notice::Event(event.sign(vec![IndexedSignature::new_both_same(sig, 0)], None, None)),
        &fx.processor,
    )
    .unwrap();
}

fn ksn_json(fx: &Fixture, id: &IdentifierPrefix) -> Value {
    let state = fx.storage.get_state(id).unwrap();
    serde_json::to_value(KeyStateNotice::new_ksn(
        state,
        KeriVersion::V1,
        SerializationFormats::JSON,
    ))
    .unwrap()
}

/// An identifier with an inception and ten interaction events: sn 10.
fn eleven_events(fx: &Fixture) -> IdentifierPrefix {
    let current = Signer::new();
    let icp = EventMsgBuilder::new(EventTypeTag::Icp)
        .with_keys(vec![key(&current)])
        .with_next_keys(vec![key(&Signer::new())])
        .build()
        .unwrap();
    let id = icp.data.get_prefix();
    process(fx, &icp, &current);
    let mut previous = icp.digest().unwrap();
    for sn in 1..=10 {
        let ixn = EventMsgBuilder::new(EventTypeTag::Ixn)
            .with_prefix(&id)
            .with_sn(sn)
            .with_previous_event(&previous)
            .build()
            .unwrap();
        process(fx, &ixn, &current);
        previous = ixn.digest().unwrap();
    }
    id
}

#[test]
fn sequence_numbers_are_hex() {
    let fx = setup();
    let id = eleven_events(&fx);
    let ksn = ksn_json(&fx, &id);
    assert_eq!(ksn["s"], "a");
    assert_eq!(ksn["et"], "ixn");

    let read: KeyStateNotice = serde_json::from_str(&ksn.to_string()).unwrap();
    assert_eq!(read.state.sn, 10);
}

#[test]
fn a_key_state_reply_past_sn_9_reads_back() {
    // The parser re-encodes each body and requires the exact bytes back, so
    // a notice written in one radix and read in another never parsed.
    let fx = setup();
    let id = eleven_events(&fx);
    let state = fx.storage.get_state(&id).unwrap();
    let witness = Signer::new();
    let witness_id = BasicPrefix::Ed25519NT(witness.public_key());
    let rpy = ReplyEvent::new_reply(
        ReplyRoute::Ksn(
            IdentifierPrefix::Basic(witness_id.clone()),
            KeyStateNotice::new_ksn(state, KeriVersion::V1, SerializationFormats::JSON),
        ),
        &IdentifierPrefix::Basic(witness_id.clone()),
        KeriVersion::V1,
        HashFunctionCode::Blake3_256,
        SerializationFormats::JSON,
    );
    let sig = SelfSigningPrefix::Ed25519Sha512(witness.sign(rpy.encode().unwrap()).unwrap());
    let cesr = Message::Op(Op::Reply(SignedReply::new_nontrans(rpy, witness_id, sig)))
        .to_cesr()
        .unwrap();

    let replies = parse_reply_stream(&cesr).unwrap();
    match replies[0].reply.get_route() {
        ReplyRoute::Ksn(_, ksn) => assert_eq!(ksn.state.sn, 10),
        other => panic!("not a key state notice: {other:?}"),
    }
}

#[test]
fn the_last_establishment_names_the_rotation_and_its_witness_changes() {
    let fx = setup();
    let (current, next) = (Signer::new(), Signer::new());
    let (w1, w2) = (
        BasicPrefix::Ed25519NT(Signer::new().public_key()),
        BasicPrefix::Ed25519NT(Signer::new().public_key()),
    );
    let icp = EventMsgBuilder::new(EventTypeTag::Icp)
        .with_keys(vec![key(&current)])
        .with_next_keys(vec![key(&next)])
        .with_witness_list(&[w1.clone()])
        .with_witness_threshold(&SignatureThreshold::Simple(0))
        .build()
        .unwrap();
    let id = icp.data.get_prefix();
    process(&fx, &icp, &current);
    let ksn = ksn_json(&fx, &id);
    assert_eq!(ksn["et"], "icp");
    assert_eq!(
        ksn["ee"],
        json!({"s": "0", "d": icp.digest().unwrap().to_string(), "br": [], "ba": []})
    );

    let rot = EventMsgBuilder::new(EventTypeTag::Rot)
        .with_prefix(&id)
        .with_sn(1)
        .with_previous_event(&icp.digest().unwrap())
        .with_keys(vec![key(&next)])
        .with_next_keys(vec![key(&Signer::new())])
        .with_witness_to_remove(&[w1.clone()])
        .with_witness_to_add(&[w2.clone()])
        .with_witness_threshold(&SignatureThreshold::Simple(0))
        .build()
        .unwrap();
    process(&fx, &rot, &next);
    let ksn = ksn_json(&fx, &id);
    assert_eq!(ksn["et"], "rot");
    assert_eq!(
        ksn["ee"],
        json!({
            "s": "1",
            "d": rot.digest().unwrap().to_string(),
            "br": [w1.to_str()],
            "ba": [w2.to_str()],
        })
    );
}

#[test]
fn a_key_state_notice_takes_the_version_of_the_query_that_asks_for_it() {
    use keri_core::{
        actor::{prelude::ReplyType, process_query},
        query::query_event::{LogsQueryArgs, QueryRoute},
    };
    let fx = setup();
    let id = eleven_events(&fx);
    let route = QueryRoute::Ksn {
        reply_route: String::new(),
        args: LogsQueryArgs {
            s: None,
            limit: None,
            i: id.clone(),
            src: None,
        },
    };
    for version in [KeriVersion::V1, KeriVersion::V2] {
        let ReplyType::Ksn(ksn) = process_query(&route, version, &fx.storage).unwrap() else {
            panic!("not a key state notice")
        };
        assert_eq!(KeriVersion::of(&ksn.serialization_info), version);

        // Carried in a reply of the same version, it reads back.
        let witness = Signer::new();
        let witness_id = BasicPrefix::Ed25519NT(witness.public_key());
        let rpy = ReplyEvent::new_reply(
            ReplyRoute::Ksn(IdentifierPrefix::Basic(witness_id.clone()), ksn),
            &IdentifierPrefix::Basic(witness_id.clone()),
            version,
            HashFunctionCode::Blake3_256,
            SerializationFormats::JSON,
        );
        let sig = SelfSigningPrefix::Ed25519Sha512(witness.sign(rpy.encode().unwrap()).unwrap());
        let cesr = Message::Op(Op::Reply(SignedReply::new_nontrans(rpy, witness_id, sig)))
            .to_cesr()
            .unwrap();
        match parse_reply_stream(&cesr).unwrap()[0].reply.get_route() {
            ReplyRoute::Ksn(_, ksn) => {
                assert_eq!(ksn.state.sn, 10);
                assert_eq!(KeriVersion::of(&ksn.serialization_info), version);
            }
            other => panic!("not a key state notice: {other:?}"),
        }
    }
}
