//! The keys an SDK rotation installs keep the identifier's transferability:
//! a transferable identifier's controlling keys use the transferable code,
//! so a group that copies a member's current key commits to a key that can
//! sign further rotations.

use std::sync::Arc;

use keri_controller::BasicPrefix;
use keri_core::signer::Signer;
use keri_sdk::advanced::{
    keys::{derive_public_key, generate_seed},
    operations,
    store::KeriStore,
    types::{IdentifierConfig, RotationConfig, SignerAlgorithm},
};

fn current_key(store: &KeriStore, alias: &str) -> (u64, BasicPrefix) {
    let id = store.load(alias).unwrap();
    let state = id.find_state(id.id()).unwrap();
    (state.sn, state.current.public_keys[0].clone())
}

#[tokio::test]
async fn rotations_keep_transferable_keys() {
    let root = tempfile::tempdir().unwrap();
    let store = KeriStore::open(root.path().to_path_buf()).unwrap();

    for (alias, config) in [
        ("ed", IdentifierConfig::default()),
        ("p256", IdentifierConfig::p256()),
    ] {
        store.create(alias, config).await.unwrap();
        for sn in 1..=2 {
            store.rotate(alias).await.unwrap();
            let (state_sn, key) = current_key(&store, alias);
            assert_eq!(state_sn, sn, "{alias}: rotation {sn} must be accepted");
            assert!(
                key.is_transferable(),
                "{alias}: rotation {sn} installed a non-transferable key {key:?}"
            );
        }
    }
}

/// Identifiers created before the fix committed to the non-transferable form
/// of their next key; rotating them must still reveal the committed form.
#[tokio::test]
async fn rotation_reveals_a_non_transferable_commitment() {
    let root = tempfile::tempdir().unwrap();
    let current_seed = generate_seed(SignerAlgorithm::Ed25519).unwrap();
    let next_seed = generate_seed(SignerAlgorithm::Ed25519).unwrap();
    let current = Arc::new(Signer::new_with_seed(&current_seed).unwrap());
    let next = Arc::new(Signer::new_with_seed(&next_seed).unwrap());

    let mut id = operations::create_identifier(
        root.path().to_path_buf(),
        current,
        derive_public_key(&next_seed, false).unwrap(),
        IdentifierConfig::default(),
    )
    .await
    .unwrap();

    let new_next_seed = generate_seed(SignerAlgorithm::Ed25519).unwrap();
    operations::rotate(
        &mut id,
        next,
        RotationConfig {
            new_next_pk: derive_public_key(&new_next_seed, true).unwrap(),
            new_next_threshold: 1,
            witness_to_add: vec![],
            witness_to_remove: vec![],
            witness_threshold: None,
        },
    )
    .await
    .unwrap();

    let state = id.find_state(id.id()).unwrap();
    assert_eq!(state.sn, 1);
    assert_eq!(
        state.current.public_keys,
        vec![derive_public_key(&next_seed, false).unwrap()]
    );
}
