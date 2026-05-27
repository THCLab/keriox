//! High-level rotate-group flow at the SDK surface.
//!
//! Each `KeriStore` alias has its own DB, so the test manually copies KEL
//! events between aliases (the production equivalent is witness/mailbox
//! forwarding). Once both members can see each other's KEL, the public
//! ergonomic surface under test is `KeriStore::rotate_multisig_group` —
//! a single call that hides signing, exchange messages, and event types.

use std::path::PathBuf;

use keri_sdk::{
    BasicPrefix, GroupRotationConfig, Identifier, IdentifierConfig, KeriStore, MultisigConfig,
    SelfSigningPrefix,
};

/// Local rotation for an alias, skipping witness notification (the test
/// runs without witnesses). Uses the next-signer because its key was
/// pre-committed at inception — its public key is what must be revealed
/// in the rot event's `keys` to match the prior pre-rotation digest.
async fn rotate_member(store: &KeriStore, alias: &str) {
    let next_signer = store.load_next_signer(alias).unwrap();
    let (new_next_seed, new_next_pk) = keri_sdk::keys::generate_ed25519(false).unwrap();
    let revealed = BasicPrefix::Ed25519NT(next_signer.public_key());
    let mut id = store.load(alias).unwrap();
    let rot = id
        .rotate(vec![revealed], vec![new_next_pk], 1, vec![], vec![], 0)
        .await
        .unwrap();
    let sig = SelfSigningPrefix::Ed25519Sha512(next_signer.sign(rot.as_bytes()).unwrap());
    id.finalize_rotate(rot.as_bytes(), sig).await.unwrap();
    store.save_rotation(alias, new_next_seed).unwrap();
}

/// Copy `src`'s own KEL into `dst`'s DB. Stand-in for what witnesses /
/// watchers do in production.
fn ingest_kel(src: &Identifier, dst: &Identifier) {
    if let Some(kel) = src.get_own_kel() {
        for notice in kel {
            dst.save_notice(&notice).unwrap();
        }
    }
}

/// Single-signer rotation: 1-of-2 group, Alice rotates Bob out.
#[tokio::test]
async fn test_store_rotate_multisig_group_evicts_member() {
    let root = tempfile::Builder::new()
        .prefix("keri-rot-group")
        .tempdir()
        .unwrap();
    let store = KeriStore::open(PathBuf::from(root.path())).unwrap();

    let (id_a, _) = store
        .create("alice", IdentifierConfig::default())
        .await
        .unwrap();
    let (id_b, _) = store
        .create("bob", IdentifierConfig::default())
        .await
        .unwrap();
    let id_a_prefix = id_a.id().clone();
    let id_b_prefix = id_b.id().clone();

    // Alice must see Bob's KEL before she can include him in the group.
    ingest_kel(&id_b, &id_a);

    let group_prefix = store
        .create_multisig_group(
            "g",
            "alice",
            MultisigConfig {
                members: vec![id_b_prefix.clone()],
                threshold: 1,
                witnesses: vec![],
                witness_threshold: 0,
                delegator: None,
            },
        )
        .await
        .unwrap();

    // Each member rotates their own KEL to reveal pre-committed next keys.
    rotate_member(&store, "alice").await;
    rotate_member(&store, "bob").await;

    // Bring Bob's post-rotation KEL into Alice's DB.
    let id_b_fresh = store.load("bob").unwrap();
    let id_a_fresh = store.load("alice").unwrap();
    ingest_kel(&id_b_fresh, &id_a_fresh);
    drop(id_a_fresh);
    drop(id_b_fresh);

    store
        .rotate_multisig_group(
            "g",
            GroupRotationConfig {
                new_participants: vec![id_a_prefix.clone()],
                new_signature_threshold: 1,
                new_next_threshold: Some(1),
                witness_to_add: vec![],
                witness_to_remove: vec![],
                witness_threshold: None,
            },
        )
        .await
        .unwrap();

    let persisted = store.load_multisig_members("g").unwrap();
    assert_eq!(persisted, vec![id_a_prefix.clone()]);

    let id_a_reload = store.load("alice").unwrap();
    let state = id_a_reload.find_state(&group_prefix).unwrap();
    assert_eq!(state.sn, 1, "rot bumps sn to 1");
    assert_eq!(state.current.public_keys.len(), 1, "only Alice remains");
    let _ = id_b_prefix;
}

/// No-op key refresh: same member set, fresh keys, threshold unchanged.
#[tokio::test]
async fn test_store_rotate_multisig_group_noop_refresh() {
    let root = tempfile::Builder::new()
        .prefix("keri-rot-noop")
        .tempdir()
        .unwrap();
    let store = KeriStore::open(PathBuf::from(root.path())).unwrap();

    let (id_a, _) = store
        .create("alice", IdentifierConfig::default())
        .await
        .unwrap();
    let (id_b, _) = store
        .create("bob", IdentifierConfig::default())
        .await
        .unwrap();
    let id_a_prefix = id_a.id().clone();
    let id_b_prefix = id_b.id().clone();

    ingest_kel(&id_b, &id_a);

    let group_prefix = store
        .create_multisig_group(
            "g",
            "alice",
            MultisigConfig {
                members: vec![id_b_prefix.clone()],
                threshold: 1,
                witnesses: vec![],
                witness_threshold: 0,
                delegator: None,
            },
        )
        .await
        .unwrap();

    let state_pre = store
        .load("alice")
        .unwrap()
        .find_state(&group_prefix)
        .unwrap();
    let old_keys = state_pre.current.public_keys.clone();

    rotate_member(&store, "alice").await;
    rotate_member(&store, "bob").await;

    let id_b_fresh = store.load("bob").unwrap();
    let id_a_fresh = store.load("alice").unwrap();
    ingest_kel(&id_b_fresh, &id_a_fresh);
    drop(id_a_fresh);
    drop(id_b_fresh);

    store
        .rotate_multisig_group(
            "g",
            GroupRotationConfig {
                new_participants: vec![id_a_prefix.clone(), id_b_prefix.clone()],
                new_signature_threshold: 1,
                new_next_threshold: Some(1),
                witness_to_add: vec![],
                witness_to_remove: vec![],
                witness_threshold: None,
            },
        )
        .await
        .unwrap();

    let state_post = store
        .load("alice")
        .unwrap()
        .find_state(&group_prefix)
        .unwrap();
    assert_eq!(state_post.sn, 1);
    assert_eq!(state_post.current.public_keys.len(), 2);
    assert_ne!(
        state_post.current.public_keys, old_keys,
        "no-op refresh must reveal new keys"
    );
    let persisted = store.load_multisig_members("g").unwrap();
    assert_eq!(persisted.len(), 2);
}
