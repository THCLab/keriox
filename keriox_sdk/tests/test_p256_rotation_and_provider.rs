//! Rotation-stays-P-256 + KeyProvider-backed P-256 inception.
//!
//! These cover the two paths most likely to be exercised by a real mobile
//! client:
//!   * A P-256 AID is rotated multiple times without silently switching
//!     curves on the next-key commitment.
//!   * A KeyProvider (the trait mobile FFI shims implement) backed by
//!     SoftwareKeyProvider with EcdsaSecp256r1 can drive inception through
//!     the SDK end-to-end.

#![cfg(feature = "keyprovider")]

use std::path::PathBuf;
use std::sync::Arc;

use keri_controller::{BasicPrefix, IdentifierPrefix};
use keri_keyprovider::{
    software::SoftwareKeyProvider, KeyProvider, SignatureAlgorithm,
};
use keri_sdk::advanced::{operations, store::KeriStore, types::IdentifierConfig, KeriSigner};

#[tokio::test]
async fn p256_rotation_stays_p256_across_multiple_rounds() {
    let root = tempfile::Builder::new()
        .prefix("p256-rot")
        .tempdir()
        .unwrap();
    let store = KeriStore::open(PathBuf::from(root.path())).unwrap();

    let (id, _) = store
        .create("alice", IdentifierConfig::p256())
        .await
        .expect("P-256 inception must succeed");
    let aid = id.id().clone();

    // Rotate three times and after each rotation re-load the AID,
    // confirming the *current* controlling key in the KEL is still P-256.
    for round in 1..=3 {
        store
            .rotate("alice")
            .await
            .unwrap_or_else(|e| panic!("rotation round {round} failed: {e:?}"));

        let id = store.load("alice").unwrap();
        let state = id
            .find_state(&aid)
            .expect("KEL state must be loadable after rotation");
        assert_eq!(state.current.public_keys.len(), 1);
        assert!(
            matches!(
                state.current.public_keys[0],
                BasicPrefix::ECDSA256r1(_) | BasicPrefix::ECDSA256r1NT(_)
            ),
            "round {round}: current key must still be a P-256 prefix, got {:?}",
            state.current.public_keys[0]
        );
    }
}

#[tokio::test]
async fn ed25519_rotation_still_stays_ed25519() {
    // Regression: the new algorithm-detecting rotate path must not
    // accidentally break the default Ed25519 case.
    let root = tempfile::Builder::new()
        .prefix("ed-rot")
        .tempdir()
        .unwrap();
    let store = KeriStore::open(PathBuf::from(root.path())).unwrap();

    let (id, _) = store
        .create("bob", IdentifierConfig::default())
        .await
        .unwrap();
    let aid = id.id().clone();

    store.rotate("bob").await.unwrap();

    let id = store.load("bob").unwrap();
    let state = id.find_state(&aid).unwrap();
    assert!(matches!(
        state.current.public_keys[0],
        BasicPrefix::Ed25519(_) | BasicPrefix::Ed25519NT(_)
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn p256_inception_through_software_keyprovider() {
    // Mobile FFI shims implement KeyProvider; this drives an inception
    // through the same trait object shape (Arc<dyn KeyProvider>) without
    // ever touching keri_core::Signer directly.
    let provider: Arc<dyn KeyProvider> = Arc::new(
        SoftwareKeyProvider::generate("mobile-key", SignatureAlgorithm::EcdsaSecp256r1).unwrap(),
    );
    let signer = KeriSigner::Provider(provider.clone());

    // Generate a matching P-256 next-key (still software-backed since
    // there is no on-device key rotation primitive here).
    let next_signer: Arc<dyn KeyProvider> = Arc::new(
        SoftwareKeyProvider::generate("mobile-next", SignatureAlgorithm::EcdsaSecp256r1).unwrap(),
    );
    let next_pk = keri_sdk::advanced::keyprovider_adapter::basic_prefix_for(
        next_signer.algorithm(),
        keri_core::keys::PublicKey::new(next_signer.public_key().bytes.clone()),
        false,
    );

    let tmp = tempfile::Builder::new().prefix("p256-kp").tempdir().unwrap();
    let db = tmp.path().join("db");

    let id = operations::create_identifier(
        db,
        signer,
        next_pk,
        IdentifierConfig::p256(), // witness/watcher empty; algorithm field unused for the next-key here
    )
    .await
    .expect("KeyProvider-backed P-256 inception must succeed");

    assert!(matches!(id.id(), IdentifierPrefix::SelfAddressing(_)));
    let state = id.find_state(id.id()).unwrap();
    assert!(matches!(
        state.current.public_keys[0],
        BasicPrefix::ECDSA256r1(_)
    ));
    assert_eq!(
        state.current.public_keys[0].signing_code().unwrap(),
        cesrox::primitives::codes::self_signing::SelfSigning::ECDSA256r1Sha256,
    );

    // Make sure the provider can still sign through the KeriSigner the
    // SDK built around it (would have panicked at inception time if
    // the algorithm dispatch were broken).
    let raw_sig = provider.sign(b"after-inception").await.unwrap();
    assert_eq!(raw_sig.len(), 64);
}
