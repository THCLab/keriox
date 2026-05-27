//! Witness-less delegation completion (Gap 1) and group KEL anchor
//! (Gap 2) end-to-end via direct CESR bytes between two `KeriStore`s.
//! Stand-in for the production transport (e.g. Iroh QUIC), or any
//! out-of-band peer channel.

use std::path::PathBuf;
use std::sync::Arc;

use keri_sdk::{
    operations, DelegationConfig, Identifier, IdentifierConfig, IdentifierPrefix, KeriStore,
    MultisigConfig, SeedPrefix, Signer,
};

fn ingest_kel(src: &Identifier, dst: &Identifier) {
    if let Some(kel) = src.get_own_kel() {
        for notice in kel {
            dst.save_notice(&notice).unwrap();
        }
    }
}

fn ingest_kel_of(src: &Identifier, kel_owner: &IdentifierPrefix, dst: &Identifier) {
    if let Some(kel) = src.get_kel(kel_owner) {
        for notice in kel {
            dst.save_notice(&notice).unwrap();
        }
    }
}

fn fresh_signer() -> (SeedPrefix, Arc<Signer>) {
    let (seed, _pk) = keri_sdk::keys::generate_ed25519(false).unwrap();
    let signer = Arc::new(Signer::new_with_seed(&seed).unwrap());
    (seed, signer)
}

// ── Gap 1: witness-less delegation ───────────────────────────────────────────

/// Single-AID delegator: Alice's own AID delegates to Bob's device AID.
#[tokio::test]
async fn test_oob_delegation_single_aid_delegator() {
    let dlg_root = tempfile::Builder::new()
        .prefix("dlg-store")
        .tempdir()
        .unwrap();
    let dvc_root = tempfile::Builder::new()
        .prefix("dvc-store")
        .tempdir()
        .unwrap();
    let dlg_store = KeriStore::open(PathBuf::from(dlg_root.path())).unwrap();

    let (alice_id, alice_signer) = dlg_store
        .create("alice", IdentifierConfig::default())
        .await
        .unwrap();
    let alice_prefix = alice_id.id().clone();

    // Bob builds the delegation request locally.
    let bob_db = dvc_root.path().join("bob_db");
    std::fs::create_dir_all(&bob_db).unwrap();
    let (_bob_seed, bob_signer) = fresh_signer();
    let (_, bob_next_pk) = keri_sdk::keys::generate_ed25519(false).unwrap();
    let (bob_id, bob_prefix, dip_cesr) = operations::build_delegation_request(
        bob_db,
        bob_signer.clone(),
        bob_next_pk,
        DelegationConfig {
            delegator: alice_prefix.clone(),
            witnesses: vec![],
            witness_threshold: 0,
            watchers: vec![],
        },
    )
    .await
    .unwrap();
    assert!(!dip_cesr.is_empty(), "dip_cesr must be non-empty");

    // Alice ingests Bob's dip so she can anchor a seal over it.
    let mut alice_mut = dlg_store.load("alice").unwrap();
    ingest_kel(&bob_id, &alice_mut);

    let signed_ixn_cesr = operations::build_delegation_approval(
        &mut alice_mut,
        &alice_signer,
        &alice_prefix,
        &dip_cesr,
        &[alice_prefix.clone()],
    )
    .await
    .unwrap();
    assert!(!signed_ixn_cesr.is_empty());

    // Bob ingests Alice's KEL (icp + new ixn) and finalises.
    ingest_kel_of(&alice_mut, &alice_prefix, &bob_id);
    operations::finalize_delegation_with_seal(&bob_id, &signed_ixn_cesr)
        .await
        .unwrap();

    let state = bob_id.find_state(&bob_prefix).unwrap();
    assert_eq!(
        state.delegator.as_ref(),
        Some(&alice_prefix),
        "delegated AID's state must point to delegator"
    );
}

/// 1-of-1 multi-sig group delegator. Same flow but delegator is a
/// group AID whose lone member is Alice.
#[tokio::test]
async fn test_oob_delegation_one_of_one_group_delegator() {
    let dlg_root = tempfile::Builder::new()
        .prefix("dlg-group")
        .tempdir()
        .unwrap();
    let dvc_root = tempfile::Builder::new()
        .prefix("dvc-group")
        .tempdir()
        .unwrap();
    let dlg_store = KeriStore::open(PathBuf::from(dlg_root.path())).unwrap();

    let (alice_id, _) = dlg_store
        .create("alice", IdentifierConfig::default())
        .await
        .unwrap();
    let alice_prefix = alice_id.id().clone();

    let group_prefix = dlg_store
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
        .unwrap();

    let bob_db = dvc_root.path().join("bob_db");
    std::fs::create_dir_all(&bob_db).unwrap();
    let (_bob_seed, bob_signer) = fresh_signer();
    let (_, bob_next_pk) = keri_sdk::keys::generate_ed25519(false).unwrap();
    let (bob_id, bob_prefix, dip_cesr) = operations::build_delegation_request(
        bob_db,
        bob_signer.clone(),
        bob_next_pk,
        DelegationConfig {
            delegator: group_prefix.clone(),
            witnesses: vec![],
            witness_threshold: 0,
            watchers: vec![],
        },
    )
    .await
    .unwrap();

    let mut alice_mut = dlg_store.load("alice").unwrap();
    ingest_kel(&bob_id, &alice_mut);

    let alice_signer = dlg_store.load_signer("alice").unwrap();
    let signed_ixn_cesr = operations::build_delegation_approval(
        &mut alice_mut,
        &alice_signer,
        &group_prefix,
        &dip_cesr,
        &[alice_prefix.clone()],
    )
    .await
    .unwrap();

    ingest_kel_of(&alice_mut, &group_prefix, &bob_id);
    operations::finalize_delegation_with_seal(&bob_id, &signed_ixn_cesr)
        .await
        .unwrap();

    let state = bob_id.find_state(&bob_prefix).unwrap();
    assert_eq!(state.delegator.as_ref(), Some(&group_prefix));
}

// ── Gap 2: group KEL anchor ──────────────────────────────────────────────────

/// 1-of-1 group anchor: one SAID seal on the group's KEL.
#[tokio::test]
async fn test_anchor_group_one_of_one() {
    use said::derivation::{HashFunction, HashFunctionCode};

    let root = tempfile::Builder::new()
        .prefix("anchor-group")
        .tempdir()
        .unwrap();
    let store = KeriStore::open(PathBuf::from(root.path())).unwrap();

    let (alice_id, _) = store
        .create("alice", IdentifierConfig::default())
        .await
        .unwrap();
    let alice_prefix = alice_id.id().clone();

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
        .unwrap();

    let payload_said = HashFunction::from(HashFunctionCode::Blake3_256)
        .derive(b"recovery-seeds-export | alice | 2026-05-27");

    let signer = store.load_signer("alice").unwrap();
    let mut alice_mut = store.load("alice").unwrap();
    operations::anchor_group(
        &mut alice_mut,
        &signer,
        &group_prefix,
        &[payload_said],
        &[alice_prefix],
    )
    .await
    .unwrap();

    let state = store
        .load("alice")
        .unwrap()
        .find_state(&group_prefix)
        .unwrap();
    assert_eq!(state.sn, 1, "ixn bumps sn from 0 to 1");
}

/// Sequential anchors on a 1-of-1 group produce ixns at sn 1, 2, 3.
#[tokio::test]
async fn test_anchor_group_sequential() {
    use said::derivation::{HashFunction, HashFunctionCode};

    let root = tempfile::Builder::new()
        .prefix("anchor-seq")
        .tempdir()
        .unwrap();
    let store = KeriStore::open(PathBuf::from(root.path())).unwrap();
    let (alice_id, _) = store
        .create("alice", IdentifierConfig::default())
        .await
        .unwrap();
    let alice_prefix = alice_id.id().clone();
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
        .unwrap();
    let signer = store.load_signer("alice").unwrap();

    for i in 1..=3u8 {
        let mut alice_mut = store.load("alice").unwrap();
        let payload_said = HashFunction::from(HashFunctionCode::Blake3_256)
            .derive(format!("anchor-{i}").as_bytes());
        operations::anchor_group(
            &mut alice_mut,
            &signer,
            &group_prefix,
            &[payload_said],
            &[alice_prefix.clone()],
        )
        .await
        .unwrap();
    }

    let state = store
        .load("alice")
        .unwrap()
        .find_state(&group_prefix)
        .unwrap();
    assert_eq!(state.sn, 3, "three ixns advance sn to 3");
}

/// OOB receive: `MultisigRequest::from_cesr` round-trips an event +
/// exchange through CESR strings without going through a witness
/// mailbox.
#[tokio::test]
async fn test_multisig_request_from_cesr_roundtrip() {
    use said::derivation::{HashFunction, HashFunctionCode};
    use keri_sdk::MultisigRequest;

    let root_a = tempfile::Builder::new().prefix("a").tempdir().unwrap();
    let root_b = tempfile::Builder::new().prefix("b").tempdir().unwrap();
    let store_a = KeriStore::open(PathBuf::from(root_a.path())).unwrap();
    let store_b = KeriStore::open(PathBuf::from(root_b.path())).unwrap();

    let (a, _) = store_a
        .create("a", IdentifierConfig::default())
        .await
        .unwrap();
    let (b, _) = store_b
        .create("b", IdentifierConfig::default())
        .await
        .unwrap();
    let _ = store_b; // both DBs are independent; ingest_kel bridges them
    let a_prefix = a.id().clone();
    let b_prefix = b.id().clone();
    ingest_kel(&b, &a);
    ingest_kel(&a, &b);

    let group_prefix = store_a
        .create_multisig_group(
            "g",
            "a",
            MultisigConfig {
                members: vec![b_prefix.clone()],
                threshold: 1,
                witnesses: vec![],
                witness_threshold: 0,
                delegator: None,
            },
        )
        .await
        .unwrap();

    let payload_said =
        HashFunction::from(HashFunctionCode::Blake3_256).derive(b"anchor-payload");
    let signer_a = store_a.load_signer("a").unwrap();
    let mut a_mut = store_a.load("a").unwrap();
    let (ixn_cesr, exns) = operations::build_group_anchor(
        &mut a_mut,
        &signer_a,
        &group_prefix,
        &[payload_said],
        &[a_prefix.clone(), b_prefix],
    )
    .await
    .unwrap();
    assert_eq!(exns.len(), 1, "one forward exchange addressed to B");

    let req = MultisigRequest::from_cesr(&ixn_cesr, &exns[0]).unwrap();
    assert_eq!(req.group_prefix(), group_prefix);
}
