//! Integration tests for `keri-sdk`.
//!
//! These tests exercise the concrete (non-generic) `Controller` / `Identifier`
//! wrappers and the new `KeriStore` + `signing` APIs. Network-dependent tests
//! (witness queries, TEL queries) are marked `#[ignore]` so that a plain
//! `cargo test -p keri-sdk` still passes in CI without live infrastructure.

use ed25519_dalek::SigningKey;
use keri_sdk::{
    signing, BasicPrefix, Controller, IdentifierConfig, IdentifierPrefix, KeriStore, SeedPrefix,
    SelfSigningPrefix, Signer,
};
use std::{path::PathBuf, sync::Arc};

// ── Helpers ──────────────────────────────────────────────────────────────────

struct KeysConfig {
    pub current: SeedPrefix,
    pub next: SeedPrefix,
}

impl Default for KeysConfig {
    fn default() -> Self {
        let current = SigningKey::generate(&mut rand::rngs::OsRng);
        let next = SigningKey::generate(&mut rand::rngs::OsRng);
        Self {
            current: SeedPrefix::RandomSeed256Ed25519(current.as_bytes().to_vec()),
            next: SeedPrefix::RandomSeed256Ed25519(next.as_bytes().to_vec()),
        }
    }
}

// ── Existing tests (unchanged logic) ─────────────────────────────────────────

#[tokio::test]
async fn test_incept_local() {
    let root = tempfile::Builder::new()
        .prefix("test-db")
        .tempdir()
        .unwrap();
    std::fs::create_dir_all(root.path()).unwrap();

    let controller = Controller::new(root.path().to_path_buf()).unwrap();

    let keys = KeysConfig::default();
    let (next_pub_key, _) = keys.next.derive_key_pair().unwrap();
    let signer = Arc::new(Signer::new_with_seed(&keys.current).unwrap());

    let public_keys = vec![BasicPrefix::Ed25519(signer.public_key())];
    let next_pub_keys = vec![BasicPrefix::Ed25519NT(next_pub_key)];

    // Generate inception event (no witnesses → no network required)
    let inception_event = controller
        .incept(public_keys.clone(), next_pub_keys, vec![], 0)
        .await
        .unwrap();

    let sig = SelfSigningPrefix::new(
        cesrox::primitives::codes::self_signing::SelfSigning::Ed25519Sha512,
        signer.sign(inception_event.as_bytes()).unwrap(),
    );

    let identifier = controller
        .finalize_incept(inception_event.as_bytes(), &sig)
        .unwrap();

    assert!(matches!(
        identifier.id(),
        IdentifierPrefix::SelfAddressing(_)
    ));
    assert!(identifier.get_own_kel().is_some());
    assert!(!identifier.get_own_kel().unwrap().is_empty());
}

#[tokio::test]
async fn test_incept_and_watcher_event_generation() {
    let root = tempfile::Builder::new()
        .prefix("test-db")
        .tempdir()
        .unwrap();
    std::fs::create_dir_all(root.path()).unwrap();

    let controller = Controller::new(root.path().to_path_buf()).unwrap();

    let keys = KeysConfig::default();
    let (next_pub_key, _) = keys.next.derive_key_pair().unwrap();
    let signer = Arc::new(Signer::new_with_seed(&keys.current).unwrap());

    let public_keys = vec![BasicPrefix::Ed25519(signer.public_key())];
    let next_pub_keys = vec![BasicPrefix::Ed25519NT(next_pub_key)];

    let inception_event = controller
        .incept(public_keys, next_pub_keys, vec![], 0)
        .await
        .unwrap();

    let sig = SelfSigningPrefix::new(
        cesrox::primitives::codes::self_signing::SelfSigning::Ed25519Sha512,
        signer.sign(inception_event.as_bytes()).unwrap(),
    );

    let identifier = controller
        .finalize_incept(inception_event.as_bytes(), &sig)
        .unwrap();

    let fake_watcher_id: IdentifierPrefix = "BNJJhjUnhlw-lsbYdehzLsX1hJMG9QJlK_wJ5AunJLrM"
        .parse()
        .unwrap();

    let rpy = identifier.add_watcher(fake_watcher_id);
    assert!(rpy.is_ok(), "add_watcher event generation failed");
}

// ── KeriStore tests ───────────────────────────────────────────────────────────

/// Create an identifier via KeriStore and verify the persisted state.
#[tokio::test]
async fn test_keri_store_create_persists() {
    let root = tempfile::Builder::new()
        .prefix("keri-store")
        .tempdir()
        .unwrap();

    let store = KeriStore::open(PathBuf::from(root.path())).unwrap();

    // Create with no witnesses (offline).
    let (identifier, _signer) = store
        .create("alice", IdentifierConfig::default())
        .await
        .unwrap();

    let id = identifier.id().clone();
    assert!(matches!(id, IdentifierPrefix::SelfAddressing(_)));

    // Verify the alias appears in the store.
    let aliases = store.list_aliases().unwrap();
    assert!(aliases.contains(&"alice".to_string()));

    // Signer can be loaded (key files were written correctly).
    let _signer2 = store.load_signer("alice").unwrap();
    let _next_signer = store.load_next_signer("alice").unwrap();
}

/// list_aliases returns only the created alias.
#[tokio::test]
async fn test_keri_store_list_aliases() {
    let root = tempfile::Builder::new()
        .prefix("keri-store")
        .tempdir()
        .unwrap();

    let store = KeriStore::open(PathBuf::from(root.path())).unwrap();
    assert!(store.list_aliases().unwrap().is_empty());

    store
        .create("bob", IdentifierConfig::default())
        .await
        .unwrap();

    let aliases = store.list_aliases().unwrap();
    assert_eq!(aliases, vec!["bob".to_string()]);
}

// ── signing module tests ──────────────────────────────────────────────────────

/// Sign a payload and verify the resulting CESR envelope (offline).
#[tokio::test]
async fn test_sign_and_verify() {
    let root = tempfile::Builder::new()
        .prefix("keri-store")
        .tempdir()
        .unwrap();

    let store = KeriStore::open(PathBuf::from(root.path())).unwrap();

    // Use the identifier directly from create — no need to reload from disk.
    let (identifier, signer) = store
        .create("carol", IdentifierConfig::default())
        .await
        .unwrap();

    let message = b"hello KERI";
    let envelope = signing::sign(&identifier, &signer, message).unwrap();

    assert_eq!(envelope.payload, message);
    assert!(!envelope.cesr.is_empty());

    let verified = signing::verify(&identifier, envelope.cesr.as_bytes()).unwrap();
    assert_eq!(verified.payload, message);
}

/// parse_signed_envelope extracts the payload and signatures.
#[tokio::test]
async fn test_parse_signed_envelope() {
    let root = tempfile::Builder::new()
        .prefix("keri-store")
        .tempdir()
        .unwrap();

    let store = KeriStore::open(PathBuf::from(root.path())).unwrap();
    let (identifier, signer) = store
        .create("dave", IdentifierConfig::default())
        .await
        .unwrap();

    let message = b"parse me";
    let envelope = signing::sign(&identifier, &signer, message).unwrap();

    let (payload, sigs) = signing::parse_signed_envelope(envelope.cesr.as_bytes()).unwrap();
    // parse_signed_envelope returns the raw JSON bytes of the CESR payload,
    // not the original bytes. Use signing::verify to get back the original payload.
    assert!(!payload.is_empty());
    assert!(!sigs.is_empty());
}
