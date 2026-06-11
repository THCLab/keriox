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

    // Alias metadata files exist (ids, seeds)…
    assert!(dir.path().join("alice").join("id").is_file());
    assert!(dir.path().join("alice").join("priv_key").is_file());
    // …but no event database was written anywhere.
    assert!(
        !dir.path().join("alice").join("db").exists(),
        "InMemory storage must not create database files"
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
