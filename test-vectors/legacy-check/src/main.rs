//! Reads `test-vectors/keriox-legacy` with keriox as deployed clients run
//! it. Every stream must parse, every key event log must leave exactly the
//! events the current keriox accepted, and every message should be written
//! back by the old keriox byte for byte. Vectors that do not are listed with
//! the reason in `expected_differences.txt`; the check fails when another
//! vector does not, and when a listed one does.

use std::{collections::BTreeMap, fs, path::Path, process::ExitCode, sync::Arc};

use keri_core::{
    actor::{parse_event_stream, process_notice},
    database::redb::RedbDatabase,
    event_message::signed_event_message::{Message, Notice},
    prefix::IdentifierPrefix,
    processor::{
        basic_processor::BasicProcessor,
        escrow::{default_escrow_bus, EscrowConfig},
        event_storage::EventStorage,
    },
};
use serde_json::{json, Value};

fn stream_bytes(vector: &Value) -> Vec<u8> {
    match (vector.get("stream"), vector.get("stream_hex")) {
        (Some(s), _) => s.as_str().unwrap().as_bytes().to_vec(),
        (_, Some(h)) => hex::decode(h.as_str().unwrap()).unwrap(),
        _ => panic!("vector {} has no stream", vector["id"]),
    }
}

/// The messages of `stream`, or why the old keriox cannot read it.
fn read(stream: &[u8]) -> Result<Vec<Message>, String> {
    std::panic::catch_unwind(|| parse_event_stream(stream))
        .map_err(|_| "parser panicked".to_string())?
        .map_err(|e| format!("does not parse: {e:?}"))
}

/// Whether the old keriox writes `messages` back as `stream`.
fn written_back(stream: &[u8], messages: &[Message]) -> Result<(), String> {
    let written: Vec<u8> = messages
        .iter()
        .map(|m| m.to_cesr().map_err(|e| format!("cannot write: {e:?}")))
        .collect::<Result<Vec<_>, _>>()?
        .concat();
    if written == stream {
        Ok(())
    } else {
        Err(format!(
            "written back as {}",
            String::from_utf8_lossy(&written)
        ))
    }
}

/// The events the old keriox accepts from `messages`, as `{prefix: [{sn, said}]}`.
fn accepted(messages: Vec<Message>, ids: &[String]) -> Value {
    let dir = tempfile::tempdir().unwrap();
    let db = Arc::new(RedbDatabase::new(&dir.path().join("db")).unwrap());
    let (bus, _escrows) = default_escrow_bus(db.clone(), EscrowConfig::default(), None);
    let processor = BasicProcessor::new(db.clone(), Some(bus));
    for message in messages {
        if let Message::Notice(notice) = message {
            let _ = process_notice(notice, &processor);
        }
    }
    let storage = EventStorage::new(db);
    let kels: serde_json::Map<String, Value> = ids
        .iter()
        .map(|id| {
            let prefix: IdentifierPrefix = id.parse().unwrap();
            let events = storage
                .get_kel_messages(&prefix)
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
            (id.clone(), Value::Array(events))
        })
        .collect();
    Value::Object(kels)
}

fn load(dir: &Path, file: &str) -> Vec<Value> {
    let text = fs::read_to_string(dir.join(file)).unwrap();
    let file: Value = serde_json::from_str(&text).unwrap();
    file["vectors"].as_array().unwrap().clone()
}

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let (dir, expected) = match (args.next(), args.next()) {
        (Some(dir), Some(expected)) => (dir, expected),
        _ => panic!("usage: keriox-legacy-check <vectors dir> <expected differences>"),
    };
    let dir = Path::new(&dir);
    let expected: BTreeMap<String, String> = fs::read_to_string(&expected)
        .unwrap()
        .lines()
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| {
            let (id, why) = l.split_once('\t').unwrap_or((l, ""));
            (id.to_string(), why.to_string())
        })
        .collect();

    let mut outcomes: BTreeMap<String, Result<(), String>> = BTreeMap::new();
    for vector in load(dir, "streams/messages.json") {
        let stream = stream_bytes(&vector);
        let outcome = read(&stream).and_then(|messages| written_back(&stream, &messages));
        outcomes.insert(vector["id"].as_str().unwrap().into(), outcome);
    }
    for vector in load(dir, "kels/kels.json") {
        let stream = stream_bytes(&vector);
        let id = vector["id"].as_str().unwrap().to_string();
        let kels = &vector["kels"];
        let ids: Vec<String> = kels.as_object().unwrap().keys().cloned().collect();
        let messages = match read(&stream) {
            Ok(messages) => messages,
            Err(e) => {
                outcomes.insert(id, Err(e));
                continue;
            }
        };
        let got = accepted(messages.clone(), &ids);
        if &got != kels {
            // not reading a log as keriox does is never expected
            println!("FAIL  {id}: accepted {got}, expected {kels}");
            return ExitCode::FAILURE;
        }
        outcomes.insert(id, written_back(&stream, &messages));
    }

    let mut wrong = 0;
    for (id, outcome) in &outcomes {
        match (outcome, expected.get(id)) {
            (Ok(()), None) => println!("ok    {id}"),
            (Err(e), Some(why)) => println!("known {id}: {why}\n      {e}"),
            (Err(e), None) => {
                wrong += 1;
                println!("FAIL  {id}: {e}");
            }
            (Ok(()), Some(_)) => {
                wrong += 1;
                println!(
                    "FAIL  {id}: now read as written, remove it from the expected differences"
                );
            }
        }
    }
    for id in expected.keys().filter(|id| !outcomes.contains_key(*id)) {
        wrong += 1;
        println!("FAIL  {id}: listed in the expected differences but not a vector");
    }
    if wrong == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
