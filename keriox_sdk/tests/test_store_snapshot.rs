//! `KeriStore::snapshot_to` — copying a store's databases while it is open.
//!
//! A backup taken from a running process cannot read the redb files
//! directly (Windows locks them), so the store writes copies of its open
//! databases. A store rebuilt from those copies plus the store's plain
//! files must load the same identifiers.

use std::path::{Path, PathBuf};

use keri_sdk::advanced::store::KeriStore;
use keri_sdk::advanced::types::IdentifierConfig;

/// Copy every file under `root` that the snapshot did not write — what a
/// backup does with the seeds and other plain files.
fn copy_plain_files(root: &Path, dest: &Path, written: &[PathBuf], rel: &Path) {
    for entry in std::fs::read_dir(root.join(rel)).unwrap() {
        let entry = entry.unwrap();
        let rel = rel.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_plain_files(root, dest, written, &rel);
        } else if !written.contains(&rel) {
            std::fs::create_dir_all(dest.join(&rel).parent().unwrap()).unwrap();
            std::fs::copy(root.join(&rel), dest.join(&rel)).unwrap();
        }
    }
}

async fn snapshot_round_trip(root: &Path, expected: &[&str]) {
    let store = KeriStore::open(root.to_path_buf()).unwrap();
    let (id, _) = store
        .create("alice", IdentifierConfig::default())
        .await
        .unwrap();
    store.rotate("alice").await.unwrap();

    let dest = tempfile::tempdir().unwrap();
    let dest = dest.path().join("snapshot");
    let mut written = store.snapshot_to(&dest).unwrap();
    written.sort();
    let mut expected: Vec<PathBuf> = expected.iter().map(PathBuf::from).collect();
    expected.sort();
    assert_eq!(written, expected);
    copy_plain_files(root, &dest, &written, Path::new(""));

    // The live store is still open: the copy is read through its handles.
    let restored = KeriStore::open(dest).unwrap();
    let alice = restored.load("alice").unwrap();
    assert_eq!(alice.id(), id.id());
    assert_eq!(alice.find_state(id.id()).unwrap().sn, 1);
    drop(store);
}

#[tokio::test]
async fn snapshot_of_a_shared_store_restores_its_identifiers() {
    let dir = tempfile::tempdir().unwrap();
    snapshot_round_trip(
        dir.path(),
        &["meta", "db/events_database", "db/query_cache"],
    )
    .await;
}

#[tokio::test]
async fn snapshot_of_a_per_alias_store_restores_its_identifiers() {
    let dir = tempfile::tempdir().unwrap();
    // A store that finds an alias database at open keeps the per-alias layout.
    std::fs::create_dir_all(dir.path().join("alice").join("db")).unwrap();
    snapshot_round_trip(
        dir.path(),
        &["meta", "alice/db/events_database", "alice/db/query_cache"],
    )
    .await;
}

#[test]
fn snapshot_refuses_a_destination_that_exists() {
    let dir = tempfile::tempdir().unwrap();
    let store = KeriStore::open(dir.path().join("store")).unwrap();
    let dest = dir.path().join("dest");
    std::fs::create_dir_all(&dest).unwrap();
    assert!(store.snapshot_to(&dest).is_err());
}
