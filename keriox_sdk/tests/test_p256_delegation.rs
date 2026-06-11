//! End-to-end witness-less delegation with P-256 keys on both sides.
//!
//! Walks the production-shape delegation flow:
//!
//!   delegatee (Bob, P-256)            delegator (Alice, P-256)
//!   ────────────────────────          ─────────────────────────
//!   build_delegation_request
//!         │
//!         │ dip CESR ───────────────────►
//!                                    ingest dip + build_delegation_approval
//!                                    (anchors dip with ixn over a seal)
//!         ◄────────────────────── signed ixn CESR + delegator KEL
//!   finalize_delegation_with_seal
//!         │
//!   delegated AID's state.delegator = Alice ✅
//!
//! Mirrors the layout of `test_layered_identity::test_oob_delegation_*`
//! but uses P-256 throughout to confirm the new algorithm-aware
//! KeriStore + Signer + delegation pipeline carries the curve end-to-end.

use std::path::PathBuf;
use std::sync::Arc;

use keri_controller::BasicPrefix;
use keri_sdk::advanced::{
    operations, DelegationConfig, Identifier, IdentifierConfig, IdentifierPrefix, KeriStore,
    SeedPrefix, Signer, SignerAlgorithm,
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

fn fresh_p256_signer() -> (SeedPrefix, Arc<Signer>) {
    let (seed, _) = keri_sdk::advanced::keys::generate_p256(false).unwrap();
    let signer = Arc::new(Signer::new_with_seed(&seed).unwrap());
    (seed, signer)
}

#[tokio::test]
async fn p256_delegation_single_aid_delegator() {
    let dlg_root = tempfile::Builder::new()
        .prefix("p256-dlg")
        .tempdir()
        .unwrap();
    let dvc_root = tempfile::Builder::new()
        .prefix("p256-dvc")
        .tempdir()
        .unwrap();
    let dlg_store = KeriStore::open(PathBuf::from(dlg_root.path())).unwrap();

    // Delegator: Alice with a P-256 AID.
    let (alice_id, alice_signer) = dlg_store
        .create("alice", IdentifierConfig::p256())
        .await
        .expect("P-256 delegator inception must succeed");
    let alice_prefix = alice_id.id().clone();

    // Delegatee: Bob also uses P-256.
    let bob_db = dvc_root.path().join("bob_db");
    std::fs::create_dir_all(&bob_db).unwrap();
    let (_bob_seed, bob_signer) = fresh_p256_signer();
    let (_, bob_next_pk) = keri_sdk::advanced::keys::generate_p256(false).unwrap();
    assert!(
        matches!(bob_next_pk, BasicPrefix::ECDSA256r1NT(_)),
        "Bob's next-key commitment must be the P-256 NT prefix"
    );

    let (bob_id, bob_prefix, dip_cesr) = operations::build_delegation_request(
        bob_db,
        bob_signer.clone(),
        bob_next_pk,
        DelegationConfig {
            delegator: alice_prefix.clone(),
            witnesses: vec![],
            witness_threshold: 0,
            watchers: vec![],
            algorithm: SignerAlgorithm::EcdsaSecp256r1,
        },
    )
    .await
    .expect("P-256 dip must build");
    assert!(!dip_cesr.is_empty());

    // Alice ingests Bob's dip and anchors a seal over it with her ixn.
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
    .expect("P-256 delegator must be able to anchor delegatee's dip");
    assert!(!signed_ixn_cesr.is_empty());

    // Bob ingests Alice's updated KEL (icp + ixn) and finalises.
    ingest_kel_of(&alice_mut, &alice_prefix, &bob_id);
    operations::finalize_delegation_with_seal(&bob_id, &signed_ixn_cesr)
        .await
        .expect("Bob must finalise the P-256 delegation");

    // Delegated AID's state must record Alice as delegator.
    let bob_state = bob_id
        .find_state(&bob_prefix)
        .expect("Bob's KEL must be loadable");
    assert_eq!(
        bob_state.delegator.as_ref(),
        Some(&alice_prefix),
        "delegated AID's state must point to delegator"
    );
    assert_eq!(bob_state.current.public_keys.len(), 1);
    assert!(
        matches!(
            bob_state.current.public_keys[0],
            BasicPrefix::ECDSA256r1(_) | BasicPrefix::ECDSA256r1NT(_)
        ),
        "delegated AID's controlling key must still be P-256, got {:?}",
        bob_state.current.public_keys[0]
    );

    // Alice's KEL after anchoring still has her P-256 controlling key.
    let alice_state = alice_mut.find_state(&alice_prefix).unwrap();
    assert!(matches!(
        alice_state.current.public_keys[0],
        BasicPrefix::ECDSA256r1(_) | BasicPrefix::ECDSA256r1NT(_)
    ));
}

#[tokio::test]
async fn mixed_curve_delegation_ed25519_delegator_p256_delegatee() {
    // Real-world shape: an existing Ed25519 organizational AID delegates
    // to a fresh P-256 device AID (the mobile-key story). Curves on the
    // two sides are independent — KERI binds delegator to delegatee via
    // the dip's `di` field and an anchor seal, not via shared key
    // material.
    let dlg_root = tempfile::Builder::new()
        .prefix("mix-dlg")
        .tempdir()
        .unwrap();
    let dvc_root = tempfile::Builder::new()
        .prefix("mix-dvc")
        .tempdir()
        .unwrap();
    let dlg_store = KeriStore::open(PathBuf::from(dlg_root.path())).unwrap();

    let (alice_id, alice_signer) = dlg_store
        .create("alice", IdentifierConfig::default()) // Ed25519
        .await
        .unwrap();
    let alice_prefix = alice_id.id().clone();

    let bob_db = dvc_root.path().join("bob_db");
    std::fs::create_dir_all(&bob_db).unwrap();
    let (_bob_seed, bob_signer) = fresh_p256_signer();
    let (_, bob_next_pk) = keri_sdk::advanced::keys::generate_p256(false).unwrap();

    let (bob_id, bob_prefix, dip_cesr) = operations::build_delegation_request(
        bob_db,
        bob_signer.clone(),
        bob_next_pk,
        DelegationConfig {
            delegator: alice_prefix.clone(),
            witnesses: vec![],
            witness_threshold: 0,
            watchers: vec![],
            algorithm: SignerAlgorithm::EcdsaSecp256r1,
        },
    )
    .await
    .unwrap();

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

    ingest_kel_of(&alice_mut, &alice_prefix, &bob_id);
    operations::finalize_delegation_with_seal(&bob_id, &signed_ixn_cesr)
        .await
        .unwrap();

    let bob_state = bob_id.find_state(&bob_prefix).unwrap();
    assert_eq!(bob_state.delegator.as_ref(), Some(&alice_prefix));
    assert!(
        matches!(
            bob_state.current.public_keys[0],
            BasicPrefix::ECDSA256r1(_) | BasicPrefix::ECDSA256r1NT(_)
        ),
        "delegatee stays on P-256 regardless of delegator's curve"
    );

    let alice_state = alice_mut.find_state(&alice_prefix).unwrap();
    assert!(
        matches!(
            alice_state.current.public_keys[0],
            BasicPrefix::Ed25519(_) | BasicPrefix::Ed25519NT(_)
        ),
        "delegator stays on Ed25519 regardless of delegatee's curve"
    );
}
