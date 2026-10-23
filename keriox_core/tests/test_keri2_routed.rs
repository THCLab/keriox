//! KERI 2.0 routed messages (`qry`, `rpy`) name their sender in `i`, right
//! after `d`, as every example of the KERI specification and KERIpy do.
//! KERI 1.0 bodies have no `i`. The sender must be the signer.
#![cfg(all(feature = "query", feature = "oobi-manager"))]

use std::sync::Arc;

use keri_core::{
    actor::{parse_op_stream, process_notice, process_reply, process_signed_query},
    database::redb::RedbDatabase,
    event_message::{
        event_msg_builder::EventMsgBuilder,
        keri_version::KeriVersion,
        signed_event_message::{Message, Notice, Op},
        EventTypeTag,
    },
    oobi::{LocationScheme, Scheme},
    oobi_manager::{OobiManager, RedbOobiManager},
    prefix::{BasicPrefix, IdentifierPrefix, IndexedSignature, SelfSigningPrefix},
    processor::{basic_processor::BasicProcessor, event_storage::EventStorage},
    query::{
        query_event::{LogsQueryArgs, QueryEvent, QueryRoute, SignedKelQuery, SignedQueryMessage},
        reply_event::{ReplyEvent, ReplyRoute, SignedReply},
    },
    signer::Signer,
};
use said::{derivation::HashFunctionCode, sad::SAD, version::format::SerializationFormats};
use tempfile::NamedTempFile;
use url::Url;

struct Fixture {
    _path: NamedTempFile,
    processor: BasicProcessor<RedbDatabase>,
    storage: EventStorage<RedbDatabase>,
    oobis: RedbOobiManager,
}

fn setup() -> Fixture {
    let path = NamedTempFile::new().unwrap();
    let db = Arc::new(RedbDatabase::new(path.path()).unwrap());
    Fixture {
        _path: path,
        processor: BasicProcessor::new(db.clone(), None),
        storage: EventStorage::new(db.clone()),
        oobis: OobiManager::new(db).unwrap(),
    }
}

/// A controller whose KERI 2.0 inception the node has accepted.
fn controller(fx: &Fixture) -> (Signer, IdentifierPrefix) {
    let signer = Signer::new();
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
    (signer, icp.data.get_prefix())
}

fn logs(about: &IdentifierPrefix, sender: &IdentifierPrefix, version: KeriVersion) -> QueryEvent {
    QueryEvent::new_query(
        QueryRoute::Logs {
            reply_route: String::new(),
            args: LogsQueryArgs {
                s: None,
                limit: None,
                i: about.clone(),
                src: None,
            },
        },
        sender,
        version,
        SerializationFormats::JSON,
        HashFunctionCode::Blake3_256,
    )
}

/// The query signed by `signer` for `signer_id`, through the wire.
fn wire_query(
    qry: QueryEvent,
    signer: &Signer,
    signer_id: &IdentifierPrefix,
) -> Result<Vec<Op>, keri_core::event_message::cesr_adapter::ParseError> {
    let sig = SelfSigningPrefix::Ed25519Sha512(signer.sign(qry.encode().unwrap()).unwrap());
    let signed = SignedKelQuery::new_trans(
        qry,
        signer_id.clone(),
        vec![IndexedSignature::new_both_same(sig, 0)],
    );
    let cesr = Message::Op(Op::Query(SignedQueryMessage::KelQuery(signed)))
        .to_cesr()
        .unwrap();
    parse_op_stream(&cesr)
}

/// The position of the top-level field `name` in a JSON body.
fn field(raw: &str, name: &str) -> usize {
    raw.find(&format!(r#""{name}":"#)).unwrap()
}

#[test]
fn a_keri_2_query_names_its_sender_after_d() {
    let fx = setup();
    let (signer, id) = controller(&fx);
    let qry = logs(&id, &id, KeriVersion::V2_0);
    let raw = String::from_utf8(qry.encode().unwrap()).unwrap();
    assert!(raw.starts_with(r#"{"v":"KERICAACAAJSON"#), "{raw}");
    assert!(field(&raw, "d") < field(&raw, "i"), "{raw}");
    assert!(field(&raw, "i") < field(&raw, "dt"), "{raw}");

    let mut ops = wire_query(qry, &signer, &id).unwrap();
    let Op::Query(qry) = ops.remove(0) else {
        panic!("not a query")
    };
    process_signed_query(qry, &fx.storage).unwrap();
}

#[test]
fn a_keri_1_query_has_no_sender() {
    let fx = setup();
    let (_signer, id) = controller(&fx);
    let raw = String::from_utf8(logs(&id, &id, KeriVersion::V1_0).encode().unwrap()).unwrap();
    assert!(raw.starts_with(r#"{"v":"KERI10JSON"#), "{raw}");
    // The only `i` is the queried identifier, inside `q`.
    assert!(field(&raw, "dt") < field(&raw, "i"), "{raw}");
}

#[test]
fn a_query_signed_by_someone_else_than_its_sender_is_refused() {
    let fx = setup();
    let (signer, id) = controller(&fx);
    let (_other_signer, other) = controller(&fx);
    assert!(wire_query(logs(&id, &other, KeriVersion::V2_0), &signer, &id).is_err());
}

fn location(eid: &BasicPrefix, sender: &IdentifierPrefix, version: KeriVersion) -> ReplyEvent {
    ReplyEvent::new_reply(
        ReplyRoute::LocScheme(LocationScheme::new(
            IdentifierPrefix::Basic(eid.clone()),
            Scheme::Http,
            Url::parse("http://a/").unwrap(),
        )),
        sender,
        version,
        HashFunctionCode::Blake3_256,
        SerializationFormats::JSON,
    )
}

fn send_reply(fx: &Fixture, rpy: ReplyEvent, signer: &Signer) -> Result<(), String> {
    let key = BasicPrefix::Ed25519NT(signer.public_key());
    let sig = SelfSigningPrefix::Ed25519Sha512(signer.sign(rpy.encode().unwrap()).unwrap());
    let cesr = Message::Op(Op::Reply(SignedReply::new_nontrans(rpy, key, sig)))
        .to_cesr()
        .unwrap();
    let mut ops = parse_op_stream(&cesr).map_err(|e| e.to_string())?;
    let Op::Reply(rpy) = ops.remove(0) else {
        panic!("not a reply")
    };
    process_reply(rpy, &fx.oobis, &fx.processor, &fx.storage).map_err(|e| e.to_string())
}

#[test]
fn a_keri_2_reply_from_its_sender_is_accepted() {
    let fx = setup();
    let signer = Signer::new();
    let eid = BasicPrefix::Ed25519NT(signer.public_key());
    let rpy = location(&eid, &IdentifierPrefix::Basic(eid.clone()), KeriVersion::V2_0);
    let raw = String::from_utf8(rpy.encode().unwrap()).unwrap();
    assert!(field(&raw, "d") < field(&raw, "i"), "{raw}");
    assert!(field(&raw, "i") < field(&raw, "dt"), "{raw}");
    send_reply(&fx, rpy, &signer).unwrap();
    assert_eq!(
        fx.oobis
            .get_loc_scheme(&IdentifierPrefix::Basic(eid))
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn a_keri_2_reply_signed_by_someone_else_than_its_sender_is_refused() {
    let fx = setup();
    let signer = Signer::new();
    let eid = BasicPrefix::Ed25519NT(signer.public_key());
    let other = IdentifierPrefix::Basic(BasicPrefix::Ed25519NT(Signer::new().public_key()));
    assert!(send_reply(&fx, location(&eid, &other, KeriVersion::V2_0), &signer).is_err());
}

/// The reply with its sender removed (`None`) or added, re-sized and
/// re-addressed so that only the `i` field is wrong.
fn with_sender(mut rpy: ReplyEvent, sender: Option<IdentifierPrefix>) -> ReplyEvent {
    rpy.data.sender = sender;
    let code = HashFunctionCode::Blake3_256;
    rpy.serialization_info.size = rpy
        .derivation_data(&code, &SerializationFormats::JSON)
        .unwrap()
        .len();
    rpy.compute_digest(&code, &SerializationFormats::JSON)
        .unwrap();
    rpy
}

#[test]
fn a_keri_2_reply_without_a_sender_is_refused() {
    let fx = setup();
    let signer = Signer::new();
    let eid = BasicPrefix::Ed25519NT(signer.public_key());
    let rpy = with_sender(
        location(&eid, &IdentifierPrefix::Basic(eid.clone()), KeriVersion::V2_0),
        None,
    );
    assert!(send_reply(&fx, rpy, &signer).is_err());
}

#[test]
fn a_keri_1_reply_with_a_sender_is_refused() {
    let fx = setup();
    let signer = Signer::new();
    let eid = BasicPrefix::Ed25519NT(signer.public_key());
    let sender = IdentifierPrefix::Basic(eid.clone());
    let rpy = with_sender(location(&eid, &sender, KeriVersion::V1_0), Some(sender));
    assert!(send_reply(&fx, rpy, &signer).is_err());
}
