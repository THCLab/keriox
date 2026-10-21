//! Shared runner for the CESR V2 test vectors in `test-vectors/v2`.
//!
//! Vectors come from several sources, one directory each; every source is
//! checked with the same rules and vector ids are prefixed with the source.
//! Included by `cesr/tests/vectors.rs` and `said/tests/vectors.rs` via
//! `#[path]`. Every vector is checked inside `catch_unwind`, so a panic is
//! recorded as a failure instead of aborting the run. The outcome set is
//! compared against the crate's expected-failure list:
//!
//! - a vector that fails but is not listed fails the test (regression),
//! - a listed vector that now passes also fails the test, so the list can
//!   only shrink as the crates catch up with the reference implementation.
//!
//! The list describes the default feature set. Optional features may make
//! more vectors pass, so with them enabled new passes are not reported.
//!
//! Run with `CESR_VECTORS_BLESS=1` to rewrite the list from the current
//! outcomes after an intentional change.

#![allow(dead_code)]

use std::{
    collections::BTreeMap,
    fmt::Write as _,
    fs,
    panic::{self, UnwindSafe},
    path::{Path, PathBuf},
};

use serde_json::Value;

const BLESS_ENV: &str = "CESR_VECTORS_BLESS";

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Outcome {
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

pub struct Runner {
    root: PathBuf,
    source: String,
    results: BTreeMap<String, (Outcome, String)>,
}

impl Runner {
    /// Returns `None` when the vector directory is absent, e.g. when the
    /// tests run from a packaged crate that does not ship the vectors.
    pub fn new(manifest_dir: &str) -> Option<Self> {
        let root = Path::new(manifest_dir).join("../test-vectors/v2");
        if !root.is_dir() {
            eprintln!("test vectors not found at {}, skipping", root.display());
            return None;
        }
        Some(Self {
            root,
            source: String::new(),
            results: BTreeMap::new(),
        })
    }

    /// The sources of vectors, one directory each.
    pub fn sources(&self) -> Vec<String> {
        let mut sources: Vec<String> = fs::read_dir(&self.root)
            .map(|entries| {
                entries
                    .flatten()
                    .filter(|e| e.path().is_dir())
                    .map(|e| e.file_name().to_string_lossy().into_owned())
                    .collect()
            })
            .unwrap_or_default();
        sources.sort();
        sources
    }

    /// Makes [`Runner::load`] and [`Runner::check`] work on `source`.
    pub fn use_source(&mut self, source: &str) {
        self.source = source.to_string();
    }

    /// The vectors of a file of the current source; none if the source does
    /// not have that file.
    pub fn load(&self, rel: &str) -> Vec<Value> {
        let path = self.root.join(&self.source).join(rel);
        if !path.exists() {
            return vec![];
        }
        let text = fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
        let file: Value = serde_json::from_str(&text)
            .unwrap_or_else(|e| panic!("cannot parse {}: {e}", path.display()));
        file["vectors"]
            .as_array()
            .unwrap_or_else(|| panic!("{} has no vectors array", path.display()))
            .clone()
    }

    /// Runs one vector check; `Err` is a failure, a panic is caught and
    /// recorded as such.
    pub fn check<F>(&mut self, id: &str, f: F)
    where
        F: FnOnce() -> Result<(), String> + UnwindSafe,
    {
        let hook = panic::take_hook();
        panic::set_hook(Box::new(|_| {}));
        let result = panic::catch_unwind(f);
        panic::set_hook(hook);

        let (outcome, message) = match result {
            Ok(Ok(())) => (Outcome::Pass, String::new()),
            Ok(Err(e)) => (Outcome::Fail, e),
            Err(p) => {
                let msg = p
                    .downcast_ref::<String>()
                    .cloned()
                    .or_else(|| p.downcast_ref::<&str>().map(|s| s.to_string()))
                    .unwrap_or_default();
                (Outcome::Panic, msg)
            }
        };
        let id = format!("{}/{id}", self.source);
        let previous = self.results.insert(id.clone(), (outcome, message));
        assert!(previous.is_none(), "vector id {id} checked twice");
    }

    /// Compares the outcomes with the expected-failure list and panics with
    /// a report if they differ. `extra_features` relaxes the check for
    /// listed vectors that pass.
    pub fn finish(self, expected_path: &str, extra_features: bool) {
        let mut summary: BTreeMap<Outcome, usize> = BTreeMap::new();
        for (outcome, _) in self.results.values() {
            *summary.entry(*outcome).or_default() += 1;
        }
        eprintln!(
            "vectors: {} pass, {} fail, {} panic",
            summary.get(&Outcome::Pass).unwrap_or(&0),
            summary.get(&Outcome::Fail).unwrap_or(&0),
            summary.get(&Outcome::Panic).unwrap_or(&0),
        );

        if std::env::var_os(BLESS_ENV).is_some() {
            assert!(
                !extra_features,
                "bless with the default feature set, the list describes it"
            );
            fs::write(expected_path, self.render_expected())
                .unwrap_or_else(|e| panic!("cannot write {expected_path}: {e}"));
            eprintln!("rewrote {expected_path}");
            return;
        }

        let expected = read_expected(expected_path);
        let mut report = String::new();
        for (id, (outcome, message)) in &self.results {
            match (outcome, expected.contains_key(id)) {
                (Outcome::Pass, true) if !extra_features => {
                    let _ = writeln!(report, "now passing, remove from list: {id}");
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
                "test vector outcomes differ from {expected_path}:\n{report}\
                 (after an intentional change run with {BLESS_ENV}=1 to update the list)"
            );
        }
    }

    fn render_expected(&self) -> String {
        let mut out = String::from(
            "# Known failures against the CESR V2 vectors in test-vectors/v2.\n\
             # Format: <source>/<vector id> TAB <fail|panic> TAB <reason>.\n\
             # Regenerate with CESR_VECTORS_BLESS=1 cargo test --test vectors.\n",
        );
        for (id, (outcome, message)) in &self.results {
            if *outcome != Outcome::Pass {
                let _ = writeln!(out, "{id}\t{}\t{}", outcome.as_str(), one_line(message));
            }
        }
        out
    }
}

fn read_expected(path: &str) -> BTreeMap<String, String> {
    let text = fs::read_to_string(path).unwrap_or_default();
    text.lines()
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| {
            let mut parts = l.splitn(2, '\t');
            let id = parts.next().unwrap_or_default().to_string();
            (id, parts.next().unwrap_or_default().to_string())
        })
        .collect()
}

fn one_line(s: &str) -> String {
    let line = s.lines().next().unwrap_or_default();
    line.chars().take(160).collect()
}

/// String field of a vector, empty if missing.
pub fn field(v: &Value, key: &str) -> String {
    v[key].as_str().unwrap_or_default().to_string()
}
