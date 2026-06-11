//! End-to-end P-256 multisig: a 1-of-1 group whose member is a P-256
//! AID, exercising both group inception and group rotation through the
//! KeriStore convenience surface.
//!
//! A 1-of-1 group is the simplest valid configuration that still goes
//! through the multisig machinery (incept_group + finalize_group_incept,
//! and rotate_group + finalize_group_rotate). It lets us prove the
//! algorithm dispatch end-to-end in a single process without standing
//! up multiple coordinated members.

use std::path::PathBuf;

use keri_controller::BasicPrefix;
use keri_sdk::advanced::{
    store::KeriStore,
    types::{GroupRotationConfig, IdentifierConfig, MultisigConfig},
};

#[tokio::test]
async fn p256_one_of_one_multisig_incept_and_rotate() {
    let root = tempfile::Builder::new()
        .prefix("p256-ms")
        .tempdir()
        .unwrap();
    let store = KeriStore::open(PathBuf::from(root.path())).unwrap();

    // 1. Member AID on P-256.
    let (member_id, _signer) = store
        .create("alice", IdentifierConfig::p256())
        .await
        .unwrap();
    let alice_prefix = member_id.id().clone();

    // 2. Form a 1-of-1 group whose lone member is Alice.
    let group_prefix = store
        .create_multisig_group(
            "g",
            "alice",
            MultisigConfig {
                members: vec![],
                threshold: 1,
                witnesses: vec![],
                witness_threshold: 0,
                delegator: None,
            },
        )
        .await
        .expect("P-256 multisig inception must succeed");

    // 3. Group's current key is Alice's P-256 key.
    let alice = store.load("alice").unwrap();
    let group_state = alice
        .find_state(&group_prefix)
        .expect("group KEL must be reachable from a member");
    assert_eq!(group_state.current.public_keys.len(), 1, "1-of-1 group");
    assert!(
        matches!(
            group_state.current.public_keys[0],
            BasicPrefix::ECDSA256r1(_) | BasicPrefix::ECDSA256r1NT(_)
        ),
        "group's lone controlling key must be Alice's P-256 prefix, got {:?}",
        group_state.current.public_keys[0]
    );

    // 4. Rotate Alice's underlying key so the group has a fresh next-key
    //    commitment ready, then rotate the group.
    store
        .rotate("alice")
        .await
        .expect("member rotation must succeed before group rotation");

    let rot_config = GroupRotationConfig {
        new_participants: vec![alice_prefix.clone()],
        new_signature_threshold: 1,
        new_next_threshold: Some(1),
        witness_to_add: vec![],
        witness_to_remove: vec![],
        witness_threshold: None,
    };
    store
        .rotate_multisig_group("g", rot_config)
        .await
        .expect("P-256 multisig rotation must succeed");

    // 5. After rotation the group's current key is still P-256 (no curve drift).
    let alice = store.load("alice").unwrap();
    let group_state = alice.find_state(&group_prefix).unwrap();
    assert_eq!(group_state.current.public_keys.len(), 1);
    assert!(
        matches!(
            group_state.current.public_keys[0],
            BasicPrefix::ECDSA256r1(_) | BasicPrefix::ECDSA256r1NT(_)
        ),
        "after rotation, group's lone controlling key must still be a P-256 prefix, got {:?}",
        group_state.current.public_keys[0]
    );
}
