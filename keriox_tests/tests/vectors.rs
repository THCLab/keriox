//! Checks keriox against the shared CESR V2 test vectors in
//! `test-vectors/v2`, a snapshot of cesrox's vectors written by keripy,
//! cesrox and the CESR specification. cesrox already checks the encoding
//! itself; these checks cover what keriox adds on top of it: its own
//! primitive types, the conversion of attachment groups into signatures,
//! turning streams into messages and processing them into a KEL, accepting
//! exactly the events of a key event log that the source accepted, SAIDs of
//! key events and rejecting what must be rejected.
//!
//! Known gaps are listed in `vectors_expected_failures.txt`, which may only
//! shrink; see `test-vectors/harness.rs` for how the list is compared and
//! rewritten.

#[path = "../../test-vectors/harness.rs"]
mod harness;

use std::{str::FromStr, sync::Arc};

use cesrox::payload::Payload;
use harness::{field, Runner};
use keri_core::{
    actor::{parse_event_stream, process_notice},
    database::redb::RedbDatabase,
    event_message::{
        cesr_adapter::{parse_cesr_stream_many, EventType},
        signature::{get_signatures, signatures_into_groups},
        signed_event_message::{Message, Notice},
    },
    prefix::{
        BasicPrefix, CesrPrimitive, IdentifierPrefix, IndexedSignature, SeedPrefix,
        SelfSigningPrefix,
    },
    processor::{
        basic_processor::BasicProcessor,
        escrow::{default_escrow_bus, EscrowConfig},
        event_storage::EventStorage,
    },
};
use said::{
    derivation::{HashFunction, HashFunctionCode},
    version::SerializationInfo,
    SelfAddressingIdentifier,
};
use serde_json::Value;

const EXPECTED: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/vectors_expected_failures.txt"
);

#[test]
fn v2_vectors() {
    let Some(mut r) = Runner::new(env!("CARGO_MANIFEST_DIR")) else {
        return;
    };
    for source in r.sources() {
        r.use_source(&source);
        primitives(&mut r);
        indexed(&mut r);
        groups(&mut r);
        streams(&mut r);
        kels(&mut r);
        migrations(&mut r);
        saids(&mut r);
        digests(&mut r);
        negative(&mut r);
    }
    r.finish(EXPECTED, false);
}

fn hex(s: &str) -> Result<Vec<u8>, String> {
    if s.len() % 2 != 0 {
        return Err(format!("odd hex length {}", s.len()));
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| e.to_string()))
        .collect()
}

/// A stream vector's bytes: text, or hex for binary and mixed streams.
fn stream_bytes(v: &Value) -> Result<Vec<u8>, String> {
    match v["stream"].as_str() {
        Some(s) => Ok(s.as_bytes().to_vec()),
        None => hex(&field(v, "stream_hex")),
    }
}

/// The keriox type a matter code name belongs to, if keriox has one.
#[derive(Clone, Copy)]
enum Family {
    Key,
    Digest,
    Signature,
    Seed,
}

fn family(name: &str) -> Option<Family> {
    Some(match name {
        "Ed25519N" | "Ed25519" | "X25519" | "ECDSA_256k1N" | "ECDSA_256k1" | "ECDSA_256r1N"
        | "ECDSA_256r1" | "Ed448N" | "Ed448" | "X448" => Family::Key,
        "Blake3_256" | "Blake2b_256" | "Blake2s_256" | "SHA3_256" | "SHA2_256" | "Blake3_512"
        | "Blake2b_512" | "SHA3_512" | "SHA2_512" => Family::Digest,
        "Ed25519_Sig" | "ECDSA_256k1_Sig" | "ECDSA_256r1_Sig" | "Ed448_Sig" => Family::Signature,
        _ if name.ends_with("_Seed") && !name.contains("Cipher") => Family::Seed,
        _ => return None,
    })
}

/// Parses `qb64` as keriox's type for `family` and writes it back.
fn reencode(family: Family, qb64: &str) -> Result<String, String> {
    let err = |e: &dyn std::fmt::Display| e.to_string();
    Ok(match family {
        Family::Key => BasicPrefix::from_str(qb64).map_err(|e| err(&e))?.to_str(),
        Family::Digest => SelfAddressingIdentifier::from_str(qb64)
            .map_err(|e| err(&e))?
            .to_string(),
        Family::Signature => SelfSigningPrefix::from_str(qb64)
            .map_err(|e| err(&e))?
            .to_str(),
        Family::Seed => SeedPrefix::from_str(qb64).map_err(|e| err(&e))?.to_str(),
    })
}

/// keriox's key, digest, signature and seed types must read the primitive
/// and write the same text back.
fn primitives(r: &mut Runner) {
    for v in r.load("primitives/fixed.json") {
        let Some(family) = family(&field(&v, "name")) else {
            continue;
        };
        let qb64 = field(&v, "qb64");
        r.check(&field(&v, "id"), move || {
            let text = reencode(family, &qb64)?;
            (text == qb64)
                .then_some(())
                .ok_or_else(|| format!("written back as {text}"))
        });
    }
}

/// Indexed signatures must read with the vector's indexes and signature.
/// keriox may write a big code as the equivalent small one, so what it
/// writes is checked by reading it back.
fn indexed(r: &mut Runner) {
    for v in r.load("indexed/indexers.json") {
        let qb64 = field(&v, "qb64");
        let (index, ondex) = (v["index"].as_u64(), v["ondex"].as_u64());
        let raw = hex(&field(&v, "raw_hex"));
        r.check(&field(&v, "id"), move || {
            let sig = IndexedSignature::from_str(&qb64).map_err(|e| e.to_string())?;
            let read = (
                Some(sig.index.current() as u64),
                sig.index.previous_next().map(u64::from),
            );
            if read != (index, ondex) {
                return Err(format!("indexes {read:?}"));
            }
            if sig.signature.derivative() != raw? {
                return Err("signature bytes differ".into());
            }
            let meaning = |s: &IndexedSignature| {
                (
                    s.index.current(),
                    s.index.previous_next(),
                    s.signature.clone(),
                )
            };
            let again = IndexedSignature::from_str(&sig.to_str()).map_err(|e| e.to_string())?;
            (meaning(&again) == meaning(&sig))
                .then_some(())
                .ok_or_else(|| format!("written as {}, which reads differently", sig.to_str()))
        });
    }
}

/// Signature groups must convert into keriox signatures, and what keriox
/// writes for them must read as the same signatures. Seal and other groups
/// carry no signatures and are skipped.
fn groups(r: &mut Runner) {
    for v in r.load("groups/groups.json") {
        let name = format!("{}{}", field(&v, "name"), field(&v, "id"));
        let signatures = [
            "ControllerIdxSigs",
            "WitnessIdxSigs",
            "NonTransReceiptCouples",
            "TransIdxSigGroups",
            "TransLastIdxSigGroups",
        ];
        if !signatures.iter().any(|s| name.contains(s)) {
            continue;
        }
        let qb64 = field(&v, "qb64");
        r.check(&field(&v, "id"), move || {
            let values = cesrox::parse(qb64.as_bytes()).map_err(|e| e.to_string())?;
            let [cesrox::Value::SpecificGroup(group)] = values.as_slice() else {
                return Err("not a single attachment group".into());
            };
            let sigs = get_signatures(group.clone()).map_err(|e| e.to_string())?;
            let written: Vec<_> = signatures_into_groups(&sigs);
            let again = written
                .into_iter()
                .map(get_signatures)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| e.to_string())?
                .concat();
            (again == sigs)
                .then_some(())
                .ok_or_else(|| "written back as different signatures".into())
        });
    }
}

/// A processor with the escrows a node runs, so that witnessed and
/// out-of-order events are handled as in production.
fn processor() -> (
    tempfile::NamedTempFile,
    BasicProcessor<RedbDatabase>,
    EventStorage<RedbDatabase>,
) {
    let path = tempfile::NamedTempFile::new().unwrap();
    let db = Arc::new(RedbDatabase::new(path.path()).unwrap());
    let (bus, _escrows) = default_escrow_bus(db.clone(), EscrowConfig::default(), None);
    (
        path,
        BasicProcessor::new(db.clone(), Some(bus)),
        EventStorage::new(db),
    )
}

/// Parses `stream` and processes its messages; every key event must end up
/// in the KEL under its own SAID, and the messages keriox writes back must
/// parse to the same messages.
fn process_stream(stream: &[u8]) -> Result<(), String> {
    let messages = parse_event_stream(stream).map_err(|e| format!("parse: {e}"))?;
    if messages.is_empty() {
        return Err("no message".into());
    }
    let (_path, processor, storage) = processor();
    let mut events = vec![];
    for message in &messages {
        if let Message::Notice(notice) = message {
            if let Notice::Event(event) = notice {
                events.push(event.event_message.clone());
            }
            process_notice(notice.clone(), &processor).map_err(|e| format!("process: {e}"))?;
        }
    }
    for event in events {
        let (id, sn) = (event.data.get_prefix(), event.data.get_sn());
        let said = event.digest().map_err(|e| e.to_string())?;
        match storage.get_event_at_sn(&id, sn) {
            Some(stored)
                if stored.signed_event_message.event_message.digest().ok()
                    == Some(said.clone()) => {}
            Some(_) => return Err(format!("{id} sn {sn}: a different event is in the KEL")),
            None => return Err(format!("{id} sn {sn} {said} was not accepted")),
        }
    }
    let written: Vec<u8> = messages
        .iter()
        .map(|m| m.to_cesr().map_err(|e| e.to_string()))
        .collect::<Result<Vec<_>, _>>()?
        .concat();
    let reparsed = parse_event_stream(&written).map_err(|e| format!("reparse: {e}"))?;
    (reparsed == messages)
        .then_some(())
        .ok_or_else(|| "written back as different messages".into())
}

fn streams(r: &mut Runner) {
    for v in r.load("streams/messages.json") {
        let stream = stream_bytes(&v);
        r.check(&field(&v, "id"), move || process_stream(&stream?));
    }
}

/// Processing a key event log must leave, for every identifier, exactly the
/// events the source accepted, in order: an event it rejects must not be in
/// keriox's KEL either.
fn kels(r: &mut Runner) {
    for v in r.load("kels/kels.json") {
        let stream = field(&v, "stream").into_bytes();
        let expected: Vec<(String, Vec<(u64, String)>)> = v["kels"]
            .as_object()
            .map(|kels| {
                kels.iter()
                    .map(|(id, events)| {
                        let events = events
                            .as_array()
                            .into_iter()
                            .flatten()
                            .map(|e| (e["sn"].as_u64().unwrap_or(u64::MAX), field(e, "said")))
                            .collect();
                        (id.clone(), events)
                    })
                    .collect()
            })
            .unwrap_or_default();
        r.check(&field(&v, "id"), move || {
            let (_path, processor, storage) = processor();
            let messages = parse_event_stream(&stream).map_err(|e| format!("parse: {e}"))?;
            for message in messages {
                if let Message::Notice(notice) = message {
                    // a rejected event is expected here; the KELs decide
                    let _ = process_notice(notice, &processor);
                }
            }
            for (id, events) in expected {
                let prefix = IdentifierPrefix::from_str(&id).map_err(|e| e.to_string())?;
                let kel: Vec<(u64, String)> = storage
                    .get_kel_messages(&prefix)
                    .map_err(|e| e.to_string())?
                    .unwrap_or_default()
                    .into_iter()
                    .filter_map(|notice| match notice {
                        Notice::Event(event) => {
                            let event = event.event_message;
                            Some((event.data.get_sn(), event.digest().ok()?.to_string()))
                        }
                        _ => None,
                    })
                    .collect();
                if kel != events {
                    return Err(format!("{id}: KEL {kel:?}, expected {events:?}"));
                }
            }
            Ok(())
        });
    }
}

/// A stream in the format of cesrox before 2.0 must read as the same
/// messages as its V2 form.
fn migrations(r: &mut Runner) {
    for v in r.load("legacy/migrate.json") {
        let (legacy, v2) = (hex(&field(&v, "legacy_hex")), hex(&field(&v, "v2_hex")));
        r.check(&field(&v, "id"), move || {
            let legacy = parse_cesr_stream_many(&legacy?).map_err(|e| format!("legacy: {e}"))?;
            let v2 = parse_cesr_stream_many(&v2?).map_err(|e| format!("v2: {e}"))?;
            let same = legacy.len() == v2.len()
                && legacy
                    .iter()
                    .zip(&v2)
                    .all(|(a, b)| a.payload == b.payload && a.attachments == b.attachments);
            same.then_some(())
                .ok_or_else(|| "legacy and V2 streams differ".into())
        });
    }
}

/// Reads a message body of `kind` as a keriox message.
fn body(kind: &str, raw: Vec<u8>) -> Result<EventType, String> {
    let payload = match kind {
        "JSON" => Payload::JSON(raw),
        "CBOR" => Payload::CBOR(raw),
        "MGPK" => Payload::MGPK(raw),
        other => return Err(format!("unsupported kind {other}")),
    };
    EventType::try_from(payload).map_err(|e| e.to_string())
}

/// keriox must accept the SAID of whole KERI messages. The SAIDs of other
/// maps are computed by the said crate, which checks them itself.
fn saids(r: &mut Runner) {
    for v in r.load("said/saidify.json") {
        if !field(&v, "id").starts_with("serder/KERI/") {
            continue;
        }
        let (kind, raw, said) = (
            field(&v, "kind"),
            hex(&field(&v, "raw_hex")),
            field(&v, "said"),
        );
        r.check(&field(&v, "id"), move || {
            let EventType::KeyEvent(event) = body(&kind, raw?)? else {
                return Err("not a key event".into());
            };
            event.check_said().map_err(|e| e.to_string())?;
            let digest = event.digest().map_err(|e| e.to_string())?.to_string();
            (digest == said)
                .then_some(())
                .ok_or_else(|| format!("SAID {digest}"))
        });
    }
}

/// Digests keriox derives must match.
fn digests(r: &mut Runner) {
    for v in r.load("said/digests.json") {
        let (code, input, qb64) = (
            field(&v, "code"),
            hex(&field(&v, "input_hex")),
            field(&v, "qb64"),
        );
        r.check(&field(&v, "id"), move || {
            let code = HashFunctionCode::from_str(&code).map_err(|e| e.to_string())?;
            let digest = HashFunction::from(code).derive(&input?).to_string();
            (digest == qb64)
                .then_some(())
                .ok_or_else(|| format!("derived {digest}"))
        });
    }
}

/// Input the source rejects must be rejected by the keriox code that reads
/// that kind of input.
fn negative(r: &mut Runner) {
    for v in r.load("negative/negative.json") {
        let (target, input) = (field(&v, "target"), field(&v, "input"));
        let kind = field(&v, "kind");
        r.check(&field(&v, "id"), move || {
            let accepted = match target.as_str() {
                "matter" => [Family::Key, Family::Digest, Family::Signature, Family::Seed]
                    .into_iter()
                    .any(|f| reencode(f, &input).is_ok()),
                "indexer" => IndexedSignature::from_str(&input).is_ok(),
                "version" => SerializationInfo::from_str(&input).is_ok(),
                "said" => match body(&kind, input.clone().into_bytes()) {
                    Ok(EventType::KeyEvent(event)) => event.check_said().is_ok(),
                    _ => false,
                },
                _ => process_stream(input.as_bytes()).is_ok(),
            };
            (!accepted)
                .then_some(())
                .ok_or_else(|| format!("{target} input accepted"))
        });
    }
}
