//! Checks keriox against the KERI protocol vectors in `test-vectors/keri`:
//! key event logs a validator must accept (`keri-kel/1`), messages it must
//! reject or must still accept (`keri-negative/1`), and the examples printed
//! in the KERI specification (`keri-spec-example/1`).
//!
//! The vectors describe what the KERI specification requires. Where keriox
//! does something else the vector is listed, with the cause, in
//! `keri_vectors_expected_failures.txt`. The list may only shrink:
//!
//! - a vector that fails but is not listed fails the test (regression),
//! - a listed vector that now passes also fails the test, so it has to be
//!   removed from the list.
//!
//! Run with `KERI_VECTORS_BLESS=1` to rewrite the list from the current
//! outcomes. Causes already in the list are kept; a new failure is written
//! with cause `unclassified` and its error message, to be classified by hand.
//! See `test-vectors/keri/README.md`.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Write as _,
    fs,
    panic::{self, AssertUnwindSafe},
    path::{Path, PathBuf},
    str::FromStr,
    sync::Arc,
};

use cesrox::payload::Payload;
use keri_core::{
    actor::{process_notice, process_reply, process_signed_exn, process_signed_query},
    database::redb::RedbDatabase,
    event::sections::{
        key_config::{KeyConfig, NextKeysData},
        seal::Seal,
        threshold::SignatureThreshold,
    },
    event_message::{
        cesr_adapter::{parse_cesr_stream_many, EventType},
        signed_event_message::{Message, Notice, Op},
    },
    oobi::Role,
    oobi_manager::OobiManager,
    prefix::{BasicPrefix, CesrPrimitive, IdentifierPrefix},
    processor::{
        basic_processor::BasicProcessor,
        escrow::{default_escrow_bus, EscrowConfig, EscrowSet},
        event_storage::EventStorage,
    },
    query::{query_event::SignedQueryMessage, reply_event::ReplyRoute},
};
use serde_json::{json, Value};

const EXPECTED: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/keri_vectors_expected_failures.txt"
);
const BLESS_ENV: &str = "KERI_VECTORS_BLESS";

#[test]
fn keri_vectors() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../test-vectors/keri");
    if !root.is_dir() {
        eprintln!("KERI vectors not found at {}, skipping", root.display());
        return;
    }
    let mut r = Runner::default();
    for file in vector_files(&root) {
        let rel = file
            .strip_prefix(&root)
            .unwrap()
            .with_extension("")
            .to_string_lossy()
            .replace('\\', "/");
        let doc: Value = serde_json::from_str(
            &fs::read_to_string(&file).unwrap_or_else(|e| panic!("{}: {e}", file.display())),
        )
        .unwrap_or_else(|e| panic!("{}: {e}", file.display()));
        let vectors = doc["vectors"].as_array().cloned().unwrap_or_default();
        r.file = rel.clone();
        match doc["schema"].as_str().unwrap_or_default() {
            "keri-kel/1" => vectors.iter().for_each(|v| kel_vector(&mut r, v)),
            "keri-negative/1" => vectors.iter().for_each(|v| negative_vector(&mut r, v)),
            "keri-spec-example/1" => {
                let by_id: BTreeMap<String, Value> =
                    vectors.iter().map(|v| (s(v, "id"), v.clone())).collect();
                vectors.iter().for_each(|v| spec_example(&mut r, v, &by_id));
            }
            other => panic!("{}: unknown schema {other}", file.display()),
        }
    }
    r.finish(EXPECTED);
}

/// The vector files: every JSON file except manifests and `edge.json`,
/// whose vectors are copies of vectors in `negative.json`.
fn vector_files(root: &Path) -> Vec<PathBuf> {
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        let Ok(entries) = fs::read_dir(dir) else {
            return;
        };
        for e in entries.flatten() {
            let p = e.path();
            if p.is_dir() {
                walk(&p, out);
            } else if p.extension().is_some_and(|x| x == "json") {
                let name = p.file_name().unwrap().to_string_lossy();
                if name != "manifest.json" && name != "edge.json" {
                    out.push(p);
                }
            }
        }
    }
    let mut files = vec![];
    for version in ["v1", "v2"] {
        walk(&root.join(version), &mut files);
    }
    files.sort();
    files
}

// ---------------------------------------------------------------------------
// runner

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Outcome {
    Pass,
    Fail,
    Panic,
}

impl Outcome {
    fn as_str(self) -> &'static str {
        match self {
            Outcome::Pass => "pass",
            Outcome::Fail => "fail",
            Outcome::Panic => "panic",
        }
    }
}

#[derive(Default)]
struct Runner {
    file: String,
    results: BTreeMap<String, (Outcome, String)>,
    per_file: BTreeMap<String, (usize, usize, usize)>,
}

impl Runner {
    /// Runs one check, catching panics; the id is prefixed with the file.
    fn check(&mut self, id: &str, f: impl FnOnce() -> Result<(), String>) {
        let hook = panic::take_hook();
        panic::set_hook(Box::new(|_| {}));
        let result = panic::catch_unwind(AssertUnwindSafe(f));
        panic::set_hook(hook);
        let (outcome, message) = match result {
            Ok(Ok(())) => (Outcome::Pass, String::new()),
            Ok(Err(e)) => (Outcome::Fail, e),
            Err(p) => (
                Outcome::Panic,
                p.downcast_ref::<String>()
                    .cloned()
                    .or_else(|| p.downcast_ref::<&str>().map(|s| s.to_string()))
                    .unwrap_or_default(),
            ),
        };
        let counts = self.per_file.entry(self.file.clone()).or_default();
        counts.0 += 1;
        if outcome == Outcome::Pass {
            counts.1 += 1;
        }
        let id = format!("{}/{id}", self.file);
        let previous = self.results.insert(id.clone(), (outcome, message));
        assert!(previous.is_none(), "vector id {id} checked twice");
    }

    /// Records a vector the runner does not check, with the reason.
    fn skip(&mut self, _id: &str) {
        self.per_file.entry(self.file.clone()).or_default().2 += 1;
    }

    fn finish(self, expected_path: &str) {
        for (file, (run, pass, skipped)) in &self.per_file {
            eprintln!(
                "{file}: {run} run, {pass} pass, {} fail, {skipped} not checked",
                run - pass
            );
        }
        let expected = read_expected(expected_path);
        if std::env::var_os(BLESS_ENV).is_some() {
            fs::write(expected_path, self.render(&expected))
                .unwrap_or_else(|e| panic!("cannot write {expected_path}: {e}"));
            eprintln!("rewrote {expected_path}");
            return;
        }
        let mut report = String::new();
        for (id, (outcome, message)) in &self.results {
            match (outcome, expected.contains_key(id)) {
                (Outcome::Pass, true) => {
                    let _ = writeln!(report, "now passing, remove from the list: {id}");
                }
                (Outcome::Fail | Outcome::Panic, false) => {
                    let _ = writeln!(
                        report,
                        "unexpected {}: {id}: {}",
                        outcome.as_str(),
                        one_line(message)
                    );
                }
                _ => {}
            }
        }
        for id in expected.keys() {
            if !self.results.contains_key(id) {
                let _ = writeln!(report, "listed but no such vector: {id}");
            }
        }
        if !report.is_empty() {
            panic!(
                "KERI vector outcomes differ from {expected_path}:\n{report}\
                 (after an intentional change run with {BLESS_ENV}=1 to update the list)"
            );
        }
    }

    fn render(&self, old: &BTreeMap<String, (String, String)>) -> String {
        let mut out = String::from(
            "# keriox against the KERI protocol vectors in test-vectors/keri: the vectors\n\
             # it does not pass today. The list may only shrink.\n\
             # Format: <file>/<vector id> TAB <cause> TAB <reason>. The causes are grouped,\n\
             # with their specification sections, in test-vectors/keri/README.md.\n\
             # Regenerate with KERI_VECTORS_BLESS=1 cargo test -p keri-tests --test keri_vectors\n\
             # (causes and reasons already listed are kept).\n",
        );
        for (id, (outcome, message)) in &self.results {
            if *outcome == Outcome::Pass {
                continue;
            }
            let (cause, reason) = old.get(id).cloned().unwrap_or_else(|| {
                (
                    "unclassified".into(),
                    format!("{}: {}", outcome.as_str(), one_line(message)),
                )
            });
            let _ = writeln!(out, "{id}\t{cause}\t{reason}");
        }
        out
    }
}

/// id -> (cause, reason)
fn read_expected(path: &str) -> BTreeMap<String, (String, String)> {
    fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .filter(|l| !l.trim().is_empty() && !l.starts_with('#'))
        .map(|l| {
            let mut parts = l.splitn(3, '\t');
            let id = parts.next().unwrap_or_default().to_string();
            let cause = parts.next().unwrap_or_default().to_string();
            let reason = parts.next().unwrap_or_default().to_string();
            (id, (cause, reason))
        })
        .collect()
}

fn one_line(s: &str) -> String {
    s.lines()
        .next()
        .unwrap_or_default()
        .chars()
        .take(200)
        .collect()
}

fn s(v: &Value, key: &str) -> String {
    v[key].as_str().unwrap_or_default().to_string()
}

fn strings(v: &Value) -> Vec<String> {
    v.as_array()
        .into_iter()
        .flatten()
        .filter_map(|x| x.as_str().map(str::to_string))
        .collect()
}

// ---------------------------------------------------------------------------
// a validator node

struct Node {
    _file: tempfile::NamedTempFile,
    processor: BasicProcessor<RedbDatabase>,
    storage: EventStorage<RedbDatabase>,
    escrows: EscrowSet<RedbDatabase>,
    oobi: OobiManager<keri_core::oobi_manager::RedbOobiStorage>,
}

/// Saids of the routed messages a node accepted, and the messages of the
/// stream it could not read.
#[derive(Default)]
struct Processed {
    accepted_ops: BTreeSet<String>,
    replies: Vec<keri_core::query::reply_event::SignedReply>,
    event_prefixes: BTreeSet<String>,
    unreadable: Vec<String>,
}

impl Node {
    /// A validator with the escrows a node runs.
    fn new() -> Self {
        let file = tempfile::NamedTempFile::new().unwrap();
        let db = Arc::new(RedbDatabase::new(file.path()).unwrap());
        let (bus, escrows) = default_escrow_bus(db.clone(), EscrowConfig::default(), None);
        Self {
            _file: file,
            processor: BasicProcessor::new(db.clone(), Some(bus)),
            // With a mailbox, as on a witness: an exchange is only kept
            // when it reaches one, so without it every exchange would fail.
            storage: EventStorage::new_redb(db.clone()),
            escrows,
            oobi: OobiManager::new(db).unwrap(),
        }
    }

    /// Processes every message of `stream` in order. Refusals are expected;
    /// what was accepted is read back from the node afterwards.
    fn process(&self, stream: &[u8]) -> Result<Processed, String> {
        let messages = parse_cesr_stream_many(stream).map_err(|e| format!("parse: {e}"))?;
        let mut out = Processed::default();
        for (i, cesr) in messages.into_iter().enumerate() {
            let message = match Message::try_from(cesr) {
                Ok(m) => m,
                Err(e) => {
                    out.unreadable.push(format!("message {i}: {e}"));
                    continue;
                }
            };
            match message {
                Message::Notice(notice) => {
                    if let Notice::Event(ev) = &notice {
                        out.event_prefixes
                            .insert(ev.event_message.data.get_prefix().to_str());
                    }
                    let _ = process_notice(notice, &self.processor);
                }
                Message::Op(Op::Reply(rpy)) => {
                    out.replies.push(rpy.clone());
                    let _ = process_reply(rpy, &self.oobi, &self.processor, &self.storage);
                }
                Message::Op(Op::Exchange(exn)) => {
                    let said = exn.exchange_message.digest().map(|d| d.to_string());
                    if process_signed_exn(exn, &self.storage).is_ok() {
                        out.accepted_ops.insert(said.unwrap_or_default());
                    }
                }
                Message::Op(Op::Query(qry)) => {
                    let said = match &qry {
                        SignedQueryMessage::KelQuery(q) => q.query.digest(),
                        SignedQueryMessage::MailboxQuery(q) => q.query.digest(),
                    }
                    .map(|d| d.to_string());
                    if process_signed_query(qry, &self.storage).is_ok() {
                        out.accepted_ops.insert(said.unwrap_or_default());
                    }
                }
            }
        }
        // a reply is accepted when the node keeps it
        for rpy in &out.replies {
            if self.reply_kept(rpy) {
                if let Ok(d) = rpy.reply.digest() {
                    out.accepted_ops.insert(d.to_string());
                }
            }
        }
        Ok(out)
    }

    fn reply_kept(&self, rpy: &keri_core::query::reply_event::SignedReply) -> bool {
        let Ok(said) = rpy.reply.digest() else {
            return false;
        };
        match rpy.reply.get_route() {
            ReplyRoute::LocScheme(lc) => self
                .oobi
                .loc_scheme_record(&lc.eid, &lc.scheme)
                .ok()
                .flatten()
                .is_some_and(|r| r.reply.digest().ok() == Some(said.clone())),
            ReplyRoute::EndRoleAdd(er) | ReplyRoute::EndRoleCut(er) => self
                .oobi
                .end_role_records(&er.cid, er.role)
                .unwrap_or_default()
                .iter()
                .any(|r| r.reply.digest().ok() == Some(said.clone())),
            ReplyRoute::Ksn(signer, ksn) => self
                .storage
                .get_last_ksn_reply(&ksn.state.prefix, &signer)
                .is_some_and(|r| r.reply.digest().ok() == Some(said.clone())),
        }
    }

    /// (sn, SAID) of the accepted events of `id`.
    fn kel(&self, id: &str) -> Result<Vec<(u64, String)>, String> {
        let prefix = IdentifierPrefix::from_str(id).map_err(|e| format!("{id}: {e}"))?;
        Ok(kel_of(&self.storage, &prefix))
    }
}

fn kel_of(storage: &EventStorage<RedbDatabase>, prefix: &IdentifierPrefix) -> Vec<(u64, String)> {
    storage
        .get_kel_messages(prefix)
        .ok()
        .flatten()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|notice| match notice {
            Notice::Event(event) => {
                let event = event.event_message;
                Some((event.data.get_sn(), event.digest().ok()?.to_string()))
            }
            _ => None,
        })
        .collect()
}

/// The `kels` of a vector: identifier -> [(sn, SAID)].
fn expected_kels(v: &Value) -> Vec<(String, Vec<(u64, String)>)> {
    v["kels"]
        .as_object()
        .into_iter()
        .flatten()
        .map(|(id, kel)| {
            let events = kel["events"]
                .as_array()
                .into_iter()
                .flatten()
                .map(|e| (e["sn"].as_u64().unwrap_or(u64::MAX), s(e, "d")))
                .collect();
            (id.clone(), events)
        })
        .collect()
}

fn compare_kels(
    kels: &[(String, Vec<(u64, String)>)],
    kel: impl Fn(&str) -> Result<Vec<(u64, String)>, String>,
) -> Result<(), String> {
    for (id, events) in kels {
        let got = kel(id)?;
        if &got != events {
            return Err(format!(
                "{id}: accepted {}, expected {}",
                show(&got),
                show(events)
            ));
        }
    }
    Ok(())
}

fn show(events: &[(u64, String)]) -> String {
    let items: Vec<String> = events
        .iter()
        .map(|(sn, d)| format!("{sn}:{}", &d[..d.len().min(8)]))
        .collect();
    format!("[{}]", items.join(" "))
}

/// The key state of `id` as KERI fields.
fn state_json(storage: &EventStorage<RedbDatabase>, id: &str) -> Result<Value, String> {
    let prefix = IdentifierPrefix::from_str(id).map_err(|e| e.to_string())?;
    let state = storage
        .get_state(&prefix)
        .ok_or_else(|| format!("{id}: no key state"))?;
    serde_json::to_value(state).map_err(|e| e.to_string())
}

fn compare_fields(what: &str, got: &Value, want: &Value, fields: &[&str]) -> Result<(), String> {
    for f in fields {
        if want.get(*f).is_some() && got.get(*f) != want.get(*f) {
            return Err(format!(
                "{what}: {f} is {}, expected {}",
                got.get(*f).unwrap_or(&Value::Null),
                want[*f]
            ));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// keri-kel/1

fn kel_vector(r: &mut Runner, v: &Value) {
    let id = s(v, "id");
    let mut streams = vec![(id.clone(), s(v, "stream"))];
    if v.get("stream_cesr1").is_some() {
        streams.push((format!("{id}/cesr1"), s(v, "stream_cesr1")));
    }
    for (vid, stream) in streams {
        let v = v.clone();
        r.check(&vid, move || {
            let node = Node::new();
            let processed = node.process(stream.as_bytes())?;
            if !processed.unreadable.is_empty() {
                return Err(format!("unreadable {}", processed.unreadable.join("; ")));
            }
            compare_kels(&expected_kels(&v), |id| node.kel(id))?;
            for (id, kel) in v["kels"].as_object().into_iter().flatten() {
                if let Some(want) = kel.get("state") {
                    let got = state_json(&node.storage, id)?;
                    compare_fields(
                        &format!("{id} state"),
                        &got,
                        want,
                        &["s", "d", "kt", "k", "nt", "n", "bt", "b"],
                    )?;
                }
            }
            Ok(())
        });
    }
}

// ---------------------------------------------------------------------------
// keri-negative/1

fn negative_vector(r: &mut Runner, v: &Value) {
    let v = v.clone();
    let id = s(&v, "id");
    match s(&v, "target").as_str() {
        "witness" => r.check(&id, move || witness_vector(&v)),
        "message" => r.check(&id, move || message_vector(&v)),
        _ => r.check(&id, move || node_vector(&v)),
    }
}

/// kel, reply, exchange, query and ksn vectors: one validator processes the
/// stream.
fn node_vector(v: &Value) -> Result<(), String> {
    let node = Node::new();
    let processed = node.process(s(v, "stream").as_bytes());
    let target = s(v, "target");
    let expected = s(v, "expected");
    let processed = match processed {
        Ok(p) => p,
        // a stream keriox cannot read at all rejects everything in it
        Err(e) if expected == "reject" && v["kels"].as_object().is_none_or(|k| k.is_empty()) => {
            let _ = e;
            return Ok(());
        }
        Err(e) => return Err(e),
    };
    compare_kels(&expected_kels(v), |id| node.kel(id))?;

    let targets = strings(&v["targets"]);
    let accepted: BTreeSet<String> = match target.as_str() {
        "kel" | "ksn" => processed
            .event_prefixes
            .iter()
            .flat_map(|p| node.kel(p).unwrap_or_default())
            .map(|(_, d)| d)
            .collect(),
        _ => processed.accepted_ops.clone(),
    };
    for t in &targets {
        match (expected.as_str(), accepted.contains(t)) {
            ("reject", true) => return Err(format!("{t} accepted")),
            ("accept", false) => {
                let why = if processed.unreadable.is_empty() {
                    String::new()
                } else {
                    format!(" (unreadable {})", processed.unreadable.join("; "))
                };
                return Err(format!("{t} not accepted{why}"));
            }
            _ => {}
        }
    }

    if let Some(wl) = v["witnesses"].as_object() {
        for (id, want) in wl {
            let got = state_json(&node.storage, id)?;
            if got["b"] != *want {
                return Err(format!("{id}: witnesses {}, expected {want}", got["b"]));
            }
        }
    }
    if let Some(evidence) = v["duplicity"].get("evidence") {
        let mut want = strings(evidence);
        want.sort();
        let mut got = vec![];
        for (id, _) in expected_kels(v) {
            let prefix = IdentifierPrefix::from_str(&id).map_err(|e| e.to_string())?;
            for e in node.escrows.duplicitous.get(&prefix).unwrap_or_default() {
                got.push(
                    e.event_message
                        .digest()
                        .map(|d| d.to_string())
                        .unwrap_or_default(),
                );
            }
        }
        got.sort();
        got.dedup();
        if got != want {
            return Err(format!("duplicity evidence {got:?}, expected {want:?}"));
        }
    }
    if let Some(want) = v.get("key_state") {
        let got = state_json(&node.storage, &s(want, "i"))?;
        compare_fields("key state", &got, want, &["i", "s", "d", "et", "b", "ee"])?;
    }
    if let Some(want) = v.get("key_state_notice") {
        let rpy = processed
            .replies
            .iter()
            .find(|r| {
                targets.contains(&r.reply.digest().map(|d| d.to_string()).unwrap_or_default())
            })
            .ok_or("no key state notice in the stream")?;
        let ReplyRoute::Ksn(_, ksn) = rpy.reply.get_route() else {
            return Err("the target is not a key state notice".into());
        };
        let got = serde_json::to_value(&ksn.state).map_err(|e| e.to_string())?;
        compare_fields("key state notice", &got, want, &["i", "s", "d"])?;
    }
    for loc in v["locs"].as_array().into_iter().flatten() {
        check_loc(&node, loc)?;
    }
    for end in v["ends"].as_array().into_iter().flatten() {
        check_end(&node, end)?;
    }
    Ok(())
}

/// A location record: `url: null` means none, `""` means nullified.
fn check_loc(node: &Node, loc: &Value) -> Result<(), String> {
    let eid = IdentifierPrefix::from_str(&s(loc, "eid")).map_err(|e| e.to_string())?;
    let scheme = s(loc, "scheme");
    let urls: Vec<String> = node
        .oobi
        .get_loc_scheme(&eid)
        .unwrap_or_default()
        .into_iter()
        .filter_map(|r| match r.get_route() {
            ReplyRoute::LocScheme(lc) => lc
                .get_url()
                .filter(|url| url.scheme() == scheme)
                .map(|url| url.to_string()),
            _ => None,
        })
        .collect();
    let last = urls.last().cloned();
    match loc["url"].as_str() {
        None if last.is_some() => Err(format!("{eid} {scheme}: location {last:?}, expected none")),
        Some("") if last.as_deref().is_some_and(|u| !u.is_empty()) => Err(format!(
            "{eid} {scheme}: location {last:?}, expected it nullified"
        )),
        Some(want) if !want.is_empty() && last.as_deref() != Some(want) => Err(format!(
            "{eid} {scheme}: location {last:?}, expected {want}"
        )),
        _ => Ok(()),
    }
}

/// An end role record: `allowed: null` means none.
fn check_end(node: &Node, end: &Value) -> Result<(), String> {
    let cid = IdentifierPrefix::from_str(&s(end, "cid")).map_err(|e| e.to_string())?;
    let eid = s(end, "eid");
    let role_name = s(end, "role");
    let role = Role::from_str(&role_name).map_err(|_| format!("unknown role {role_name}"))?;
    let records = node.oobi.end_role_records(&cid, role).unwrap_or_default();
    let last = records
        .iter()
        .rev()
        .find_map(|r| match r.reply.get_route() {
            ReplyRoute::EndRoleAdd(er) if er.eid.to_str() == eid => Some(true),
            ReplyRoute::EndRoleCut(er) if er.eid.to_str() == eid => Some(false),
            _ => None,
        });
    let want = end["allowed"].as_bool();
    let ok = match want {
        None => last.is_none(),
        Some(true) => last == Some(true),
        Some(false) => last != Some(true),
    };
    ok.then_some(())
        .ok_or_else(|| format!("{cid} {role_name} {eid}: allowed {last:?}, expected {want:?}"))
}

/// A message vector: whether keriox reads the body as a KERI message whose
/// SAID verifies.
fn message_vector(v: &Value) -> Result<(), String> {
    let messages =
        parse_cesr_stream_many(s(v, "stream").as_bytes()).map_err(|e| format!("parse: {e}"));
    let targets = strings(&v["targets"]);
    let mut accepted = BTreeSet::new();
    let mut errors = vec![];
    for m in messages.unwrap_or_else(|e| {
        errors.push(e);
        vec![]
    }) {
        match EventType::try_from(m.payload)
            .map_err(|e| e.to_string())
            .and_then(|e| said_of(&e))
        {
            Ok(said) => {
                accepted.insert(said);
            }
            Err(e) => errors.push(e),
        }
    }
    for t in &targets {
        match (s(v, "expected").as_str(), accepted.contains(t)) {
            ("reject", true) => return Err(format!("{t} read as a valid message")),
            ("accept", false) => {
                return Err(format!("{t} not read: {}", errors.join("; ")));
            }
            _ => {}
        }
    }
    Ok(())
}

/// The message's SAID, after checking it.
fn said_of(event: &EventType) -> Result<String, String> {
    let e = |e: keri_core::error::Error| e.to_string();
    Ok(match event {
        EventType::KeyEvent(ev) => {
            ev.check_said().map_err(e)?;
            ev.digest().map_err(e)?.to_string()
        }
        EventType::Receipt(rct) => rct.receipted_event_digest.to_string(),
        EventType::Exn(exn) => {
            exn.check_digest().map_err(e)?;
            exn.digest().map_err(e)?.to_string()
        }
        EventType::Qry(qry) => {
            qry.check_digest().map_err(e)?;
            qry.digest().map_err(e)?.to_string()
        }
        EventType::MailboxQry(qry) => {
            qry.check_digest().map_err(e)?;
            qry.digest().map_err(e)?.to_string()
        }
        EventType::Rpy(rpy) => {
            rpy.check_digest().map_err(e)?;
            rpy.digest().map_err(e)?.to_string()
        }
    })
}

/// A witness vector: the stream is delivered to the witness named in the
/// vector, started from `witness_seed`.
fn witness_vector(v: &Value) -> Result<(), String> {
    let dir = tempfile::tempdir().map_err(|e| e.to_string())?;
    let seed = s(v, "witness_seed");
    let witness = witness::Witness::setup_with_redb(
        "http://witness.example/".parse().unwrap(),
        dir.path(),
        (!seed.is_empty()).then_some(seed),
        witness::WitnessEscrowConfig::default(),
    )
    .map_err(|e| e.to_string())?;
    let name = s(v, "witness");
    if !name.is_empty() && witness.prefix.to_str() != name {
        return Err(format!(
            "witness_seed gives {}, not {name}",
            witness.prefix.to_str()
        ));
    }
    let mut events = vec![];
    for m in parse_cesr_stream_many(s(v, "stream").as_bytes()).map_err(|e| e.to_string())? {
        let notice = Notice::try_from(m).map_err(|e| e.to_string())?;
        if let Notice::Event(ev) = &notice {
            events.push(ev.event_message.clone());
        }
        let _ = witness.process_notice(notice);
    }
    let storage = &witness.event_storage;
    compare_kels(&expected_kels(v), |id| {
        let prefix = IdentifierPrefix::from_str(id).map_err(|e| e.to_string())?;
        Ok(kel_of(storage, &prefix))
    })?;
    if v["witness_receipts"]
        .as_array()
        .is_some_and(|r| r.is_empty())
    {
        for ev in events {
            let (prefix, sn) = (ev.data.get_prefix(), ev.data.get_sn());
            if let Some(rct) = storage.get_nt_receipts(&prefix, sn).ok().flatten() {
                if rct.body.receipted_event_digest == ev.digest().map_err(|e| e.to_string())? {
                    return Err(format!("the witness receipted {prefix} sn {sn}"));
                }
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// keri-spec-example/1

fn spec_example(r: &mut Runner, v: &Value, by_id: &BTreeMap<String, Value>) {
    let id = s(v, "id");
    let v = v.clone();
    match s(&v, "type").as_str() {
        "message" => r.check(&id, move || spec_message(&v)),
        "seal" => r.check(&id, move || spec_seal(&v)),
        "threshold" => r.check(&id, move || spec_threshold(&v)),
        "key-list" => {
            let of = by_id.get(&s(&v, "next_of")).cloned();
            r.check(&id, move || spec_key_list(&v, of))
        }
        // native CESR field encodings and salts: no keriox API reads them
        // on their own
        _ => r.skip(&id),
    }
}

/// A printed message must read as a KERI message; when the example is
/// consistent its SAID must verify too. Where the extractor found the
/// content malformed (a key where a digest belongs, a url without scheme)
/// the message must be refused instead. Field order errata do not count:
/// they come from the specification contradicting itself about `i` in
/// routed messages, and the examples follow keripy.
fn spec_message(v: &Value) -> Result<(), String> {
    let malformed = v["errata"]
        .as_array()
        .into_iter()
        .flatten()
        .any(|e| e.as_str().is_some_and(|e| !e.starts_with("fields [")));
    let read = read_spec_message(v);
    if malformed {
        return match read {
            Ok(()) => Err("malformed example read as a valid message".into()),
            Err(_) => Ok(()),
        };
    }
    read
}

fn read_spec_message(v: &Value) -> Result<(), String> {
    let raw = s(v, "raw").into_bytes();
    let payload = match s(v, "kind").as_str() {
        "JSON" => Payload::JSON(raw),
        "CBOR" => Payload::CBOR(raw),
        "MGPK" => Payload::MGPK(raw),
        "CESR" => {
            // a native body: through the stream parser, as it would arrive
            let mut m = parse_cesr_stream_many(&raw).map_err(|e| format!("parse: {e}"))?;
            if m.len() != 1 {
                return Err(format!("{} messages", m.len()));
            }
            m.remove(0).payload
        }
        other => return Err(format!("unsupported kind {other}")),
    };
    let event = EventType::try_from(payload).map_err(|e| format!("read: {e}"))?;
    if v["consistent"].as_bool() == Some(true) && v["checks"].get("said").is_some() {
        let said = said_of(&event)?;
        let want = s(&v["sad"], "d");
        if said != want {
            return Err(format!("SAID {said}, expected {want}"));
        }
    }
    Ok(())
}

/// A seal must read as a keriox seal and be written back with the same
/// fields; a seal the specification prints with a malformed value must be
/// refused.
fn spec_seal(v: &Value) -> Result<(), String> {
    let sad = v["sad"].clone();
    let malformed = v["errata"]
        .as_array()
        .into_iter()
        .flatten()
        .any(|e| e.as_str().is_some_and(|e| e.contains("non-Base64")));
    let read = serde_json::from_str::<Seal>(&sad.to_string());
    if malformed {
        return match read {
            Ok(_) => Err("malformed seal accepted".into()),
            Err(_) => Ok(()),
        };
    }
    let seal = read.map_err(|e| format!("read: {e}"))?;
    let back = serde_json::to_value(&seal).map_err(|e| e.to_string())?;
    (back == sad)
        .then_some(())
        .ok_or_else(|| format!("written back as {back}"))
}

/// A threshold must read as a keriox threshold and be written back the
/// same.
fn spec_threshold(v: &Value) -> Result<(), String> {
    let value = v["value"].clone();
    let t: SignatureThreshold =
        serde_json::from_str(&value.to_string()).map_err(|e| format!("read: {e}"))?;
    let back = serde_json::to_value(&t).map_err(|e| e.to_string())?;
    (back == value)
        .then_some(())
        .ok_or_else(|| format!("written back as {back}"))
}

/// The next keys an example reveals must satisfy the commitment (`nt`, `n`)
/// of the example they belong to.
fn spec_key_list(v: &Value, of: Option<Value>) -> Result<(), String> {
    let of = of.ok_or("no such example")?;
    // through text: keriox's thresholds read hex numbers from borrowed strings
    let commitment: NextKeysData =
        serde_json::from_str(&json!({"nt": of["sad"]["nt"], "n": of["sad"]["n"]}).to_string())
            .map_err(|e| format!("commitment: {e}"))?;
    let keys = strings(&v["value"])
        .iter()
        .map(|k| BasicPrefix::from_str(k).map_err(|e| format!("{k}: {e}")))
        .collect::<Result<Vec<_>, _>>()?;
    let unused = NextKeysData::new(SignatureThreshold::Simple(0), vec![]);
    let next = KeyConfig::new(keys, unused, None);
    match commitment.verify_next(&next) {
        Ok(true) => Ok(()),
        Ok(false) => Err("keys do not satisfy the commitment".into()),
        Err(e) => Err(format!("keys do not satisfy the commitment: {e}")),
    }
}
