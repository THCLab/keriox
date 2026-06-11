//! Full SDK inception with a P-256 (secp256r1) key.
//!
//! Exercises the Signer dispatch path end-to-end:
//!   keri_sdk::advanced::keys::generate_p256_seed -> KeriStore::create_with_seeds
//!     -> Signer::new_with_seed (algorithm-aware)
//!     -> create_identifier_with_controller (Signer.basic_prefix + Signer.signing_code)
//!     -> Controller.incept + Controller.finalize_incept
//!     -> AID prefix bytes = SEC1-compressed P-256 verfer

use std::path::PathBuf;

use keri_controller::{BasicPrefix, IdentifierPrefix};
use keri_sdk::advanced::{store::KeriStore, types::IdentifierConfig};

#[tokio::test]
async fn p256_full_inception_through_sdk() {
    let root = tempfile::Builder::new()
        .prefix("p256-icp")
        .tempdir()
        .unwrap();
    let store = KeriStore::open(PathBuf::from(root.path())).unwrap();

    let current_seed = keri_sdk::advanced::keys::generate_p256_seed().unwrap();
    let next_seed = keri_sdk::advanced::keys::generate_p256_seed().unwrap();

    let (id, signer) = store
        .create_with_seeds(
            "p256-alice",
            current_seed,
            next_seed,
            IdentifierConfig::default(),
        )
        .await
        .expect("P-256 inception must succeed through the SDK");

    // AIDs born from inception events are SAIDs (hash of the inception),
    // not basic prefixes — so we only check that inception produced one and
    // that the KEL records the P-256 controlling key.
    let aid = id.id();
    assert!(matches!(aid, IdentifierPrefix::SelfAddressing(_)));

    let state = id.find_state(aid).expect("KEL must hold inception state");
    assert_eq!(state.current.public_keys.len(), 1, "single-key inception");
    assert!(
        matches!(state.current.public_keys[0], BasicPrefix::ECDSA256r1(_)),
        "current controlling key must be transferable P-256, got {:?}",
        state.current.public_keys[0]
    );

    // Sign through the Signer that the store built. This proves the
    // algorithm-aware dispatch is wired up in keri_core::Signer.
    let msg = b"inception payload";
    let raw_sig = signer.sign(msg).expect("Signer must sign with P-256");
    assert_eq!(raw_sig.len(), 64, "P-256 signature must be raw 64-byte r||s");
    assert_eq!(
        signer.signing_code(),
        cesrox::primitives::codes::self_signing::SelfSigning::ECDSA256r1Sha256
    );

    // Verify via the BasicPrefix the store derived for the controlling key.
    let controlling_pk = signer.basic_prefix(true);
    let sig_prefix =
        keri_controller::SelfSigningPrefix::ECDSA256r1Sha256(raw_sig);
    assert!(
        controlling_pk.verify(msg, &sig_prefix).unwrap(),
        "Signer.sign must produce a signature that verifies under Signer.basic_prefix"
    );
}

#[tokio::test]
async fn p256_inception_then_reload_still_signs_p256() {
    let root = tempfile::Builder::new()
        .prefix("p256-reload")
        .tempdir()
        .unwrap();
    let store = KeriStore::open(PathBuf::from(root.path())).unwrap();

    let current_seed = keri_sdk::advanced::keys::generate_p256_seed().unwrap();
    let next_seed = keri_sdk::advanced::keys::generate_p256_seed().unwrap();

    let (_id, _signer) = store
        .create_with_seeds(
            "p256-bob",
            current_seed,
            next_seed,
            IdentifierConfig::default(),
        )
        .await
        .unwrap();

    // Reload the signer from disk to make sure new_with_seed correctly
    // re-infers the P-256 algorithm from the persisted seed string.
    let reloaded = store.load_signer("p256-bob").unwrap();
    assert_eq!(
        reloaded.signing_code(),
        cesrox::primitives::codes::self_signing::SelfSigning::ECDSA256r1Sha256
    );
    let sig = reloaded.sign(b"after-reload").unwrap();
    assert_eq!(sig.len(), 64);
}
