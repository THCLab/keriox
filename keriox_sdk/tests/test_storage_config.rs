//! Storage backends and store embedding.
//!
//! Covers the two SDK extensions requested by embedders (Kotlin bindings):
//! - `StorageConfig::InMemory` — event databases on redb's in-memory
//!   backend, nothing persisted;
//! - `Keri::from_store` — building the facade around an existing
//!   `KeriStore` without a second (lock-colliding) open of the databases.

use std::sync::Arc;

use keri_sdk::advanced::store::KeriStore;
use keri_sdk::advanced::types::{IdentifierConfig, StorageConfig};
use keri_sdk::Keri;

#[tokio::test]
async fn in_memory_store_keeps_event_databases_off_disk() {
    let dir = tempfile::tempdir().unwrap();
    let store =
        KeriStore::open_with_storage(dir.path().to_path_buf(), StorageConfig::InMemory).unwrap();

    let (id, signer) = store
        .create("alice", IdentifierConfig::default())
        .await
        .unwrap();

    // Everything works: sign, verify, rotate.
    let envelope = keri_sdk::advanced::signing::sign(&id, &signer, b"in memory").unwrap();
    let verified = keri_sdk::advanced::signing::verify(&id, envelope.cesr.as_bytes()).unwrap();
    assert_eq!(verified.payload, b"in memory");
    store.rotate("alice").await.unwrap();

    // Alias metadata lives in the (here: in-memory) metadata database, not
    // in files; only the seeds are on disk, via the default file-backed
    // secrets store.
    assert!(!dir.path().join("alice").join("id").exists());
    assert!(dir.path().join("alice").join("priv_key").is_file());
    assert!(store.has_alias("alice"));
    // No event database was written anywhere.
    assert!(
        !dir.path().join("alice").join("db").exists(),
        "InMemory storage must not create database files"
    );
    assert!(
        !dir.path().join("db").exists(),
        "InMemory storage must not create a shared database file"
    );
}

#[tokio::test]
async fn in_memory_facade_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let keri = Keri::open_with_storage(dir.path(), keri_sdk::StorageConfig::InMemory).unwrap();

    let alice = keri.new_identity("alice").build().await.unwrap();
    let signed = alice.sign(b"ephemeral identity").await.unwrap();
    assert_eq!(
        keri.verify(signed.as_cesr()).unwrap().payload,
        b"ephemeral identity"
    );
    alice.rotate().await.unwrap();

    assert!(!dir.path().join("alice").join("db").exists());
}

#[tokio::test]
async fn in_memory_with_memory_secrets_touches_no_files_at_all() {
    let dir = tempfile::tempdir().unwrap();
    let store = KeriStore::open_with_options(
        dir.path().to_path_buf(),
        StorageConfig::InMemory,
        Arc::new(keri_sdk::advanced::MemorySecretsStore::new()),
    )
    .unwrap();

    let (id, signer) = store
        .create("alice", IdentifierConfig::default())
        .await
        .unwrap();
    let envelope = keri_sdk::advanced::signing::sign(&id, &signer, b"diskless").unwrap();
    keri_sdk::advanced::signing::verify(&id, envelope.cesr.as_bytes()).unwrap();
    store.rotate("alice").await.unwrap();

    let entries: Vec<_> = std::fs::read_dir(dir.path()).unwrap().collect();
    assert!(
        entries.is_empty(),
        "fully ephemeral store must not write anything, found: {entries:?}"
    );
}

#[tokio::test]
async fn new_stores_share_one_event_database() {
    let dir = tempfile::tempdir().unwrap();
    let store = KeriStore::open(dir.path().to_path_buf()).unwrap();

    store.create("alice", IdentifierConfig::default()).await.unwrap();
    store.create("bob", IdentifierConfig::default()).await.unwrap();

    // One database for the whole store; no per-alias databases.
    assert!(dir.path().join("db").is_dir());
    assert!(!dir.path().join("alice").join("db").exists());
    assert!(!dir.path().join("bob").join("db").exists());

    // Both identities work over the shared database, also after reopen.
    drop(store);
    let store = KeriStore::open(dir.path().to_path_buf()).unwrap();
    assert!(store.load("alice").is_ok());
    assert!(store.load("bob").is_ok());
    assert_eq!(store.list_aliases().unwrap(), vec!["alice", "bob"]);
}

#[tokio::test]
async fn legacy_per_alias_stores_keep_their_layout() {
    let dir = tempfile::tempdir().unwrap();
    // Simulate a store created by an older SDK version: an alias directory
    // with its own database.
    std::fs::create_dir_all(dir.path().join("old-alias").join("db")).unwrap();

    let store = KeriStore::open(dir.path().to_path_buf()).unwrap();
    store.create("bob", IdentifierConfig::default()).await.unwrap();

    // New aliases follow the store's existing per-alias layout — no shared
    // database appears next to legacy data.
    assert!(dir.path().join("bob").join("db").is_dir());
    assert!(!dir.path().join("db").exists());

    // The decision is persisted: still per-alias after reopen.
    drop(store);
    let store = KeriStore::open(dir.path().to_path_buf()).unwrap();
    store.create("carol", IdentifierConfig::default()).await.unwrap();
    assert!(dir.path().join("carol").join("db").is_dir());
    assert!(!dir.path().join("db").exists());
}

#[tokio::test]
async fn legacy_metadata_files_migrate_on_read() {
    let dir = tempfile::tempdir().unwrap();
    // A field written by an older SDK version as a plain file.
    std::fs::create_dir_all(dir.path().join("alice")).unwrap();
    std::fs::write(dir.path().join("alice").join("reg_id"), "EXAMPLE_REGISTRY").unwrap();

    let store = KeriStore::open(dir.path().to_path_buf()).unwrap();
    assert_eq!(
        store.read_meta("alice", "reg_id").unwrap().as_deref(),
        Some("EXAMPLE_REGISTRY")
    );

    // The value was migrated into the metadata database: deleting the
    // legacy file does not lose it.
    std::fs::remove_file(dir.path().join("alice").join("reg_id")).unwrap();
    assert_eq!(
        store.read_meta("alice", "reg_id").unwrap().as_deref(),
        Some("EXAMPLE_REGISTRY")
    );
}

#[tokio::test]
async fn facade_embeds_an_existing_store_without_lock_collision() {
    let dir = tempfile::tempdir().unwrap();

    // The embedder's app already owns a store with a live identifier.
    let store = Arc::new(KeriStore::open(dir.path().to_path_buf()).unwrap());
    let (_id, _signer) = store
        .create("alice", IdentifierConfig::default())
        .await
        .unwrap();

    // Building the facade around the SAME store shares its controller
    // cache — no second redb open, no "Database already open" error
    // (which is exactly what a second Keri::open on this path would hit).
    let keri = Keri::from_store(store.clone());
    let alice = keri.identity("alice").expect("no lock collision");

    let signed = alice.sign(b"one cache, two layers").await.unwrap();
    assert_eq!(
        keri.verify(signed.as_cesr()).unwrap().payload,
        b"one cache, two layers"
    );

    // Both layers stay usable side by side on the shared instance.
    assert_eq!(keri.store().list_aliases().unwrap(), vec!["alice"]);
    assert_eq!(store.root(), dir.path());
}
