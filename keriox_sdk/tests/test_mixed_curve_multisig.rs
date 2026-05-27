//! Mixed-curve 2-of-2 multisig inception with direct member-to-member
//! signature routing (no witnesses, no mailbox).
//!
//! Proves that the algorithm-aware Signer + per-index SelfSigning
//! dispatch carry an inception event across two members whose
//! controlling keys are on different curves: Alice on Ed25519, Bob
//! on P-256. Each member signs the canonical icp bytes with their own
//! curve, the SDK helper [`multisig::merge_group_signatures`]
//! assembles a single fully-signed Notice, and both sides ingest it.
//! After ingestion both members observe the group AID with both
//! members' BasicPrefixes in the current key set.

use std::path::PathBuf;
use std::sync::Arc;

use keri_controller::{BasicPrefix, IdentifierPrefix, SelfSigningPrefix};
use keri_sdk::{
    multisig, store::KeriStore, types::IdentifierConfig, Identifier, Signer,
};

fn ingest_kel(src: &Identifier, dst: &Identifier) {
    if let Some(kel) = src.get_own_kel() {
        for notice in kel {
            dst.save_notice(&notice).unwrap();
        }
    }
}

/// Sign `bytes` with `signer` and wrap in the right SelfSigningPrefix variant.
fn sign_curve(signer: &Arc<Signer>, bytes: &[u8]) -> SelfSigningPrefix {
    let raw = signer.sign(bytes).unwrap();
    SelfSigningPrefix::new(signer.signing_code(), raw)
}

#[tokio::test]
async fn mixed_curve_2_of_2_multisig_inception() {
    // Two separate stores stand in for two devices. Alice is Ed25519,
    // Bob is P-256.
    let alice_root = tempfile::Builder::new()
        .prefix("mix-ms-alice")
        .tempdir()
        .unwrap();
    let bob_root = tempfile::Builder::new()
        .prefix("mix-ms-bob")
        .tempdir()
        .unwrap();
    let alice_store = KeriStore::open(PathBuf::from(alice_root.path())).unwrap();
    let bob_store = KeriStore::open(PathBuf::from(bob_root.path())).unwrap();

    let (alice_id, alice_signer) = alice_store
        .create("alice", IdentifierConfig::default()) // Ed25519
        .await
        .unwrap();
    let (bob_id, bob_signer) = bob_store
        .create("bob", IdentifierConfig::p256()) // P-256
        .await
        .unwrap();
    let bob_prefix = bob_id.id().clone();

    assert_eq!(alice_signer.signing_code(), keri_sdk::cesrox::primitives::codes::self_signing::SelfSigning::Ed25519Sha512);
    assert_eq!(bob_signer.signing_code(), keri_sdk::cesrox::primitives::codes::self_signing::SelfSigning::ECDSA256r1Sha256);

    // Each side must know the other's individual KEL before it can
    // verify or build a group event over them.
    ingest_kel(&bob_id, &alice_id);
    ingest_kel(&alice_id, &bob_id);

    // Alice (the initiator) builds the canonical icp + the exchange
    // messages addressed to Bob. We only need icp_cesr for the
    // co-signing dance — witnesses are out of scope here.
    let (icp_cesr, _exns) = alice_id
        .incept_group(
            vec![bob_prefix.clone()],
            2,       // 2-of-2 signature threshold
            Some(2), // 2-of-2 next-key threshold
            None,
            None,
            None,
        )
        .expect("alice must build group icp over a known peer");
    let icp_bytes = icp_cesr.as_bytes();

    // Each member signs the same canonical bytes with their own curve.
    let alice_sig = sign_curve(&alice_signer, icp_bytes);
    let bob_sig = sign_curve(&bob_signer, icp_bytes);

    // Assemble a single fully-signed group inception notice. The
    // helper attaches both indexed signatures, each carrying its own
    // SelfSigning code, so verifiers dispatch per-index.
    let signed_notice = multisig::merge_group_signatures(
        icp_bytes,
        vec![(0, alice_sig), (1, bob_sig)],
    )
    .expect("merge must succeed for a valid icp");

    // Both sides ingest the same fully-signed notice. The escrow
    // resolves immediately because all signatures are attached.
    alice_id.save_notice(&signed_notice).unwrap();
    bob_id.save_notice(&signed_notice).unwrap();

    // Derive the group prefix from the signed event and confirm both
    // members converged to the same group state with the right curves
    // in the current key set.
    let group_prefix: IdentifierPrefix = if let keri_sdk::keri_core::event_message::signed_event_message::Notice::Event(ev) = &signed_notice {
        ev.event_message.data.get_prefix()
    } else {
        panic!("merge_group_signatures must return Notice::Event");
    };

    for (label, id) in [("alice", &alice_id), ("bob", &bob_id)] {
        let state = id
            .find_state(&group_prefix)
            .unwrap_or_else(|_| panic!("{label}: group state must be present after ingest"));
        assert_eq!(state.current.public_keys.len(), 2, "{label}: 2-of-2 keys");
        assert!(
            matches!(
                state.current.public_keys[0],
                BasicPrefix::Ed25519(_) | BasicPrefix::Ed25519NT(_)
            ),
            "{label}: index 0 must be Ed25519 (Alice), got {:?}",
            state.current.public_keys[0]
        );
        assert!(
            matches!(
                state.current.public_keys[1],
                BasicPrefix::ECDSA256r1(_) | BasicPrefix::ECDSA256r1NT(_)
            ),
            "{label}: index 1 must be P-256 (Bob), got {:?}",
            state.current.public_keys[1]
        );
    }
}
