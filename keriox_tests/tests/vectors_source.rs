//! Writes what keriox produces as test vectors, in the layout of the shared
//! CESR V2 vectors: in CESR V2 in `test-vectors/keriox`, so that another
//! implementation can confirm it (`test-vectors/keripy-check.sh` reads them
//! with keripy), and in the format keriox wrote before cesrox 2.0 in
//! `test-vectors/keriox-legacy`, which deployed keriox clients must keep
//! reading (`test-vectors/legacy-check.sh`).
//!
//! Keys and timestamps are fixed, so the vectors are the same on every run.
//! The test regenerates them and fails if they differ from the committed
//! files; run it with `KERIOX_VECTORS_WRITE=1` to rewrite them after an
//! intentional change.

use std::{collections::BTreeMap, fs, path::Path, sync::Arc};

use chrono::DateTime;
use keri_core::{
    actor::{parse_event_stream, process_notice},
    database::redb::RedbDatabase,
    event::{
        event_data::InceptionEvent,
        sections::{
            key_config::{nxt_commitment, KeyConfig},
            seal::{DigestSeal, EventSeal, Seal, SourceSeal},
            threshold::SignatureThreshold,
        },
        KeyEvent,
    },
    event_message::{
        cesr_adapter::WireFormat,
        event_msg_builder::{EventMsgBuilder, ReceiptBuilder},
        msg::KeriEvent,
        signature::{Nontransferable, Signature, SignerData},
        signed_event_message::{
            Message, Notice, Op, SignedNontransferableReceipt, SignedTransferableReceipt,
        },
        timestamped::Timestamped,
        EventTypeTag,
    },
    mailbox::exchange::{Exchange, ForwardTopic, FwdArgs, SignedExchange},
    oobi::{EndRole, LocationScheme, Role, Scheme},
    prefix::{BasicPrefix, CesrPrimitive, IdentifierPrefix, IndexedSignature, SelfSigningPrefix},
    processor::{
        basic_processor::BasicProcessor,
        escrow::{default_escrow_bus, EscrowConfig},
        event_storage::EventStorage,
    },
    query::{
        query_event::{LogsQueryArgs, QueryRoute, SignedKelQuery, SignedQueryMessage},
        reply_event::{ReplyRoute, SignedReply},
    },
    signer::Signer,
};
use said::{
    derivation::{HashFunction, HashFunctionCode},
    version::format::SerializationFormats,
};
use serde_json::{json, Value};

const OUT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../test-vectors");
const WRITE_ENV: &str = "KERIOX_VECTORS_WRITE";
const TIMESTAMP: &str = "2024-01-01T00:00:00+00:00";

/// A signer whose key is derived from `label`.
fn signer(label: &str) -> Signer {
    let seed = HashFunction::from(HashFunctionCode::Blake3_256)
        .derive(format!("keriox/vectors/{label}").as_bytes())
        .derivative();
    Signer::new_with_key(&seed.try_into().unwrap()).unwrap()
}

fn key(s: &Signer) -> BasicPrefix {
    BasicPrefix::Ed25519(s.public_key())
}

fn witness_key(s: &Signer) -> BasicPrefix {
    BasicPrefix::Ed25519NT(s.public_key())
}

fn sign(data: &[u8], signers: &[&Signer]) -> Vec<IndexedSignature> {
    signers
        .iter()
        .enumerate()
        .map(|(i, s)| {
            let sig = SelfSigningPrefix::Ed25519Sha512(s.sign(data).unwrap());
            IndexedSignature::new_both_same(sig, i as u16)
        })
        .collect()
}

fn text(format: WireFormat, message: Message) -> String {
    String::from_utf8(message.to_cesr_with(format).unwrap()).unwrap()
}

fn signed_event(format: WireFormat, event: &KeriEvent<KeyEvent>, signers: &[&Signer]) -> String {
    let sigs = sign(&event.encode().unwrap(), signers);
    text(
        format,
        Message::Notice(Notice::Event(event.sign(sigs, None, None))),
    )
}

fn timestamped<D: serde::Serialize>(data: D) -> Timestamped<D> {
    Timestamped {
        sender: None,
        timestamp: DateTime::parse_from_rfc3339(TIMESTAMP).unwrap(),
        data,
    }
}

/// The events keriox accepts from `stream` for each identifier, as
/// `{prefix: [{sn, said}]}`.
fn keriox_kels(stream: &str, ids: &[&IdentifierPrefix]) -> Value {
    let path = tempfile::NamedTempFile::new().unwrap();
    let db = Arc::new(RedbDatabase::new(path.path()).unwrap());
    let (bus, _escrows) = default_escrow_bus(db.clone(), EscrowConfig::default(), None);
    let processor = BasicProcessor::new(db.clone(), Some(bus));
    for message in parse_event_stream(stream.as_bytes()).unwrap() {
        if let Message::Notice(notice) = message {
            let _ = process_notice(notice, &processor);
        }
    }
    let storage = EventStorage::new(db);
    let kels: serde_json::Map<String, Value> = ids
        .iter()
        .map(|id| {
            let events: Vec<Value> = storage
                .get_kel_messages(id)
                .unwrap()
                .unwrap_or_default()
                .into_iter()
                .filter_map(|n| match n {
                    Notice::Event(e) => Some(json!({
                        "sn": e.event_message.data.get_sn(),
                        "said": e.event_message.digest().unwrap().to_string(),
                    })),
                    _ => None,
                })
                .collect();
            (id.to_string(), Value::Array(events))
        })
        .collect();
    Value::Object(kels)
}

fn kel_vector(
    id: &str,
    note: &str,
    stream: String,
    ids: &[&IdentifierPrefix],
    counts: &[usize],
) -> Value {
    let kels = keriox_kels(&stream, ids);
    let got: Vec<usize> = ids
        .iter()
        .map(|i| kels[i.to_string()].as_array().unwrap().len())
        .collect();
    assert_eq!(
        got, counts,
        "{id}: keriox accepted other events than intended"
    );
    json!({"id": id, "note": note, "pvrsn": "1.0", "stream": stream, "kels": kels})
}

fn kels(format: WireFormat) -> Vec<Value> {
    let (c0, c1, c2) = (signer("c0"), signer("c1"), signer("c2"));
    let (n0, n1, n2) = (signer("n0"), signer("n1"), signer("n2"));
    let (m0, m1, m2) = (signer("m0"), signer("m1"), signer("m2"));
    let two = SignatureThreshold::Simple(2);
    let mut vecs = vec![];

    // inception, rotation and interaction of a 2-of-3 identifier
    let icp = EventMsgBuilder::new(EventTypeTag::Icp)
        .with_keys(vec![key(&c0), key(&c1), key(&c2)])
        .with_threshold(&two)
        .with_next_keys(vec![key(&n0), key(&n1), key(&n2)])
        .with_next_threshold(&two)
        .build()
        .unwrap();
    let id = icp.data.get_prefix();
    let rot = EventMsgBuilder::new(EventTypeTag::Rot)
        .with_prefix(&id)
        .with_sn(1)
        .with_previous_event(&icp.digest().unwrap())
        .with_keys(vec![key(&n0), key(&n1), key(&n2)])
        .with_threshold(&two)
        .with_next_keys(vec![key(&m0), key(&m1), key(&m2)])
        .with_next_threshold(&two)
        .build()
        .unwrap();
    let anchored = HashFunction::from(HashFunctionCode::Blake3_256).derive(b"anchored data");
    let ixn = EventMsgBuilder::new(EventTypeTag::Ixn)
        .with_prefix(&id)
        .with_sn(2)
        .with_previous_event(&rot.digest().unwrap())
        .with_seal(vec![Seal::Digest(DigestSeal::new(anchored))])
        .build()
        .unwrap();
    let kel = [
        signed_event(format, &icp, &[&c0, &c1, &c2]),
        signed_event(format, &rot, &[&n0, &n1, &n2]),
        signed_event(format, &ixn, &[&n0, &n1, &n2]),
    ]
    .concat();
    vecs.push(kel_vector(
        "kel/icp-rot-ixn",
        "inception with 2 of 3 signatures required, rotation to the pre-committed keys, \
         interaction anchoring a digest",
        kel.clone(),
        &[&id],
        &[3],
    ));

    // a transferable receipt of that inception by another identifier
    let (v0, vn) = (signer("validator"), signer("validator/next"));
    let validator = EventMsgBuilder::new(EventTypeTag::Icp)
        .with_keys(vec![key(&v0)])
        .with_next_keys(vec![key(&vn)])
        .build()
        .unwrap();
    let receipt = ReceiptBuilder::default()
        .with_receipted_event(icp.clone())
        .build()
        .unwrap();
    let vrc = SignedTransferableReceipt::new(
        receipt,
        EventSeal::new(validator.data.get_prefix(), 0, validator.digest().unwrap()),
        sign(&icp.encode().unwrap(), &[&v0]),
    );
    vecs.push(kel_vector(
        "kel/transferable-receipt",
        "a second identifier receipts the first one's inception with a -X group",
        [
            signed_event(format, &validator, &[&v0]),
            signed_event(format, &icp, &[&c0, &c1, &c2]),
            text(format, Message::Notice(Notice::TransferableRct(vrc))),
        ]
        .concat(),
        &[&validator.data.get_prefix(), &id],
        &[1, 1],
    ));

    // an inception with two witnesses and a threshold of 2
    let (w0, w1) = (signer("witness0"), signer("witness1"));
    let witnessed = EventMsgBuilder::new(EventTypeTag::Icp)
        .with_keys(vec![key(&c0)])
        .with_next_keys(vec![key(&n0)])
        .with_witness_list(&[witness_key(&w0), witness_key(&w1)])
        .with_witness_threshold(&SignatureThreshold::Simple(2))
        .build()
        .unwrap();
    let wid = witnessed.data.get_prefix();
    let raw = witnessed.encode().unwrap();
    let receipt = ReceiptBuilder::default()
        .with_receipted_event(witnessed.clone())
        .build()
        .unwrap();
    let receipts: String = [&w0, &w1]
        .iter()
        .map(|w| {
            let sig = SelfSigningPrefix::Ed25519Sha512(w.sign(&raw).unwrap());
            text(
                format,
                Message::Notice(Notice::NontransferableRct(
                    SignedNontransferableReceipt::new(
                        &receipt,
                        vec![Nontransferable::Couplet(vec![(witness_key(w), sig)])],
                    ),
                )),
            )
        })
        .collect();
    vecs.push(kel_vector(
        "kel/witnessed-receipts",
        "inception with two witnesses followed by a receipt from each",
        signed_event(format, &witnessed, &[&c0]) + &receipts,
        &[&wid],
        &[1],
    ));
    let wigers = sign(&raw, &[&w0, &w1]);
    let with_wigers = witnessed.sign(
        sign(&raw, &[&c0]),
        Some(vec![Nontransferable::Indexed(wigers)]),
        None,
    );
    vecs.push(kel_vector(
        "kel/witnessed-indexed",
        "inception with two witnesses whose indexed signatures are attached",
        text(format, Message::Notice(Notice::Event(with_wigers))),
        &[&wid],
        &[1],
    ));

    // delegation: the delegator anchors the delegated inception and rotation
    let (d0, dn, dnn) = (
        signer("delegator"),
        signer("delegator/next"),
        signer("delegator/next2"),
    );
    let delegator = EventMsgBuilder::new(EventTypeTag::Icp)
        .with_keys(vec![key(&d0)])
        .with_next_keys(vec![key(&dn)])
        .build()
        .unwrap();
    let dor = delegator.data.get_prefix();
    let dip = EventMsgBuilder::new(EventTypeTag::Dip)
        .with_delegator(&dor)
        .with_keys(vec![key(&c0)])
        .with_next_keys(vec![key(&n0)])
        .build()
        .unwrap();
    let dee = dip.data.get_prefix();
    let anchor_dip = EventMsgBuilder::new(EventTypeTag::Ixn)
        .with_prefix(&dor)
        .with_sn(1)
        .with_previous_event(&delegator.digest().unwrap())
        .with_seal(vec![Seal::Event(EventSeal::new(
            dee.clone(),
            0,
            dip.digest().unwrap(),
        ))])
        .build()
        .unwrap();
    let drt = EventMsgBuilder::new(EventTypeTag::Drt)
        .with_prefix(&dee)
        .with_sn(1)
        .with_previous_event(&dip.digest().unwrap())
        .with_keys(vec![key(&n0)])
        .with_next_keys(vec![key(&dnn)])
        .build()
        .unwrap();
    let anchor_drt = EventMsgBuilder::new(EventTypeTag::Ixn)
        .with_prefix(&dor)
        .with_sn(2)
        .with_previous_event(&anchor_dip.digest().unwrap())
        .with_seal(vec![Seal::Event(EventSeal::new(
            dee.clone(),
            1,
            drt.digest().unwrap(),
        ))])
        .build()
        .unwrap();
    let delegated =
        |event: &KeriEvent<KeyEvent>, signer: &Signer, anchor: &KeriEvent<KeyEvent>, sn| {
            let sigs = sign(&event.encode().unwrap(), &[signer]);
            let seal = SourceSeal::new(sn, anchor.digest().unwrap());
            text(
                format,
                Message::Notice(Notice::Event(event.sign(sigs, None, Some(seal)))),
            )
        };
    vecs.push(kel_vector(
        "kel/delegated",
        "delegator inception and interactions anchoring a delegated inception and a \
         delegated rotation, each citing its anchor",
        [
            signed_event(format, &delegator, &[&d0]),
            signed_event(format, &anchor_dip, &[&d0]),
            delegated(&dip, &c0, &anchor_dip, 1),
            signed_event(format, &anchor_drt, &[&d0]),
            delegated(&drt, &n0, &anchor_drt, 2),
        ]
        .concat(),
        &[&dor, &dee],
        &[3, 2],
    ));
    vecs
}

fn stream_vector(id: &str, note: &str, stream: String, verkeys: &[&Signer]) -> Value {
    let mut v = json!({"id": id, "note": note, "stream": stream});
    if !verkeys.is_empty() {
        v["sigs_verkeys"] = json!(verkeys.iter().map(|s| key(s).to_str()).collect::<Vec<_>>());
    }
    v
}

fn streams(format: WireFormat) -> Vec<Value> {
    let (c0, n0) = (signer("c0"), signer("n0"));
    let icp = EventMsgBuilder::new(EventTypeTag::Icp)
        .with_keys(vec![key(&c0)])
        .with_next_keys(vec![key(&n0)])
        .build()
        .unwrap();
    let id = icp.data.get_prefix();
    let seal = EventSeal::new(id.clone(), 0, icp.digest().unwrap());
    let witness = signer("witness0");
    let mut vecs = vec![stream_vector(
        "stream/icp/JSON",
        "single-key inception with its controller signature",
        signed_event(format, &icp, &[&c0]),
        &[&c0],
    )];

    // a key state query signed with the signer's last establishment event
    let qry = KeriEvent::new(
        keri_core::event_message::keri_version::KeriVersion::V1,
        SerializationFormats::JSON,
        HashFunctionCode::Blake3_256.into(),
        timestamped(QueryRoute::Ksn {
            reply_route: "".into(),
            args: LogsQueryArgs {
                s: None,
                limit: None,
                i: id.clone(),
                src: None,
            },
        }),
    );
    let sigs = sign(&qry.encode().unwrap(), &[&c0]);
    vecs.push(stream_vector(
        "stream/qry/ksn",
        "key state query signed with a -Y group",
        text(
            format,
            Message::Op(Op::Query(SignedQueryMessage::KelQuery(
                SignedKelQuery::new_trans(qry, id.clone(), sigs),
            ))),
        ),
        &[],
    ));

    // replies: an end role by a transferable controller, a location by a witness
    let reply = |route| {
        KeriEvent::new(
            keri_core::event_message::keri_version::KeriVersion::V1,
            SerializationFormats::JSON,
            HashFunctionCode::Blake3_256.into(),
            timestamped(route),
        )
    };
    let end_role = reply(ReplyRoute::EndRoleAdd(EndRole {
        cid: id.clone(),
        role: Role::Witness,
        eid: IdentifierPrefix::Basic(witness_key(&witness)),
    }));
    let sigs = sign(&end_role.encode().unwrap(), &[&c0]);
    vecs.push(stream_vector(
        "stream/rpy/end-role/transferable",
        "end role reply signed by a transferable controller with a -X group",
        text(
            format,
            Message::Op(Op::Reply(SignedReply::new_trans(
                end_role,
                seal.clone(),
                sigs,
            ))),
        ),
        &[],
    ));
    let loc = reply(ReplyRoute::LocScheme(LocationScheme {
        eid: IdentifierPrefix::Basic(witness_key(&witness)),
        scheme: Scheme::Http,
        url: Some("http://witness.example:5631/".parse().unwrap()),
    }));
    let sig = SelfSigningPrefix::Ed25519Sha512(witness.sign(loc.encode().unwrap()).unwrap());
    vecs.push(stream_vector(
        "stream/rpy/loc-scheme/nontransferable",
        "location reply signed by a witness with a receipt couple",
        text(
            format,
            Message::Op(Op::Reply(SignedReply::new_nontrans(
                loc,
                witness_key(&witness),
                sig,
            ))),
        ),
        &[],
    ));

    // an exchange forwarding an event, signed by the sender and the event's
    // signature attached under its path
    let exn = KeriEvent::new(
        keri_core::event_message::keri_version::KeriVersion::V1,
        SerializationFormats::JSON,
        HashFunctionCode::Blake3_256.into(),
        timestamped(Exchange::Fwd {
            args: FwdArgs {
                recipient_id: id.clone(),
                topic: ForwardTopic::Multisig,
            },
            to_forward: icp.clone(),
        }),
    );
    let exn_sigs = sign(&exn.encode().unwrap(), &[&c0]);
    let icp_sigs = sign(&icp.encode().unwrap(), &[&c0]);
    let exchange = SignedExchange {
        exchange_message: exn,
        signature: vec![Signature::Transferable(
            SignerData::EventSeal(seal.clone()),
            exn_sigs,
        )],
        data_signature: (
            cesrox::cesr_proof::MaterialPath::create_from_str("-a".into()).unwrap(),
            vec![Signature::Transferable(
                SignerData::EventSeal(seal),
                icp_sigs,
            )],
        ),
    };
    vecs.push(stream_vector(
        "stream/exn/fwd",
        "exchange forwarding an inception, with the sender's -X group and the \
         inception's signatures under path -a",
        text(format, Message::Op(Op::Exchange(exchange))),
        &[],
    ));

    // the inception in CBOR and MessagePack
    for (serialization, name) in [
        (SerializationFormats::CBOR, "CBOR"),
        (SerializationFormats::MGPK, "MGPK"),
    ] {
        let key_config = KeyConfig::new(
            vec![key(&c0)],
            nxt_commitment(
                SignatureThreshold::Simple(1),
                &[key(&n0)],
                &HashFunctionCode::Blake3_256.into(),
            ),
            Some(SignatureThreshold::Simple(1)),
        );
        let icp = InceptionEvent::new(key_config, None, None)
            .incept_self_addressing(
                keri_core::event_message::keri_version::KeriVersion::V1,
                HashFunctionCode::Blake3_256.into(),
                serialization,
            )
            .unwrap();
        let stream = Message::Notice(Notice::Event(icp.sign(
            sign(&icp.encode().unwrap(), &[&c0]),
            None,
            None,
        )))
        .to_cesr_with(format)
        .unwrap();
        vecs.push(json!({
            "id": format!("stream/icp/{name}"),
            "note": format!("single-key inception in {name}"),
            "stream_hex": stream.iter().map(|b| format!("{b:02x}")).collect::<String>(),
            "sigs_verkeys": [key(&c0).to_str()],
        }));
    }
    vecs
}

fn files(format: WireFormat) -> BTreeMap<&'static str, Value> {
    let generator = json!({
        "tool": "keriox_tests/tests/vectors_source.rs",
        "version": "0.1.0",
        "source": {"implementation": "keriox", "version": env!("CARGO_PKG_VERSION")},
    });
    let file = |schema: &str, vectors: Vec<Value>| json!({"schema": schema, "generator": generator, "vectors": vectors});
    let (kels, streams) = (kels(format), streams(format));
    let manifest = json!({
        "generator": generator,
        "files": {"kels/kels.json": kels.len(), "streams/messages.json": streams.len()},
    });
    BTreeMap::from([
        ("kels/kels.json", file("kel/1", kels)),
        ("streams/messages.json", file("stream/1", streams)),
        ("manifest.json", manifest),
    ])
}

#[test]
fn keriox_vectors() {
    let write = std::env::var_os(WRITE_ENV).is_some();
    for (dir, format) in [
        ("keriox", WireFormat::V2),
        ("keriox-legacy", WireFormat::Legacy),
    ] {
        check_or_write(&Path::new(OUT).join(dir), format, write);
    }
}

fn check_or_write(dir: &Path, format: WireFormat, write: bool) {
    for (rel, value) in files(format) {
        let path = dir.join(rel);
        let text = serde_json::to_string_pretty(&value).unwrap() + "\n";
        if write {
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(&path, text).unwrap();
        } else {
            // Compared as JSON, not as text: which order a map's keys are
            // written in depends on serde_json features this crate does not
            // control, and none of the vectors' content lives in it.
            let committed = fs::read_to_string(&path).unwrap_or_default();
            let committed: Option<Value> = serde_json::from_str(&committed).ok();
            assert!(
                committed.as_ref() == Some(&value),
                "{} differs from what keriox writes now; after an intentional \
                 change run with {WRITE_ENV}=1",
                path.display()
            );
        }
    }
}
