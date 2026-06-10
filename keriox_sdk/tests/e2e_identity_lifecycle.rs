//! End-to-end: the full lifecycle of a single identity.
//!
//! This test doubles as a tutorial. It walks through everything an
//! application does with one identity over its lifetime: create it behind a
//! witness, sign data, verify it, rotate keys, and pick the identity up
//! again after a restart.

mod common;

use common::TestInfra;
use test_context::test_context;

#[test_context(TestInfra)]
#[actix_rt::test]
async fn identity_lifecycle(infra: &mut TestInfra) {
    // ── Create ────────────────────────────────────────────────────────────
    // One call: the facade fetches the witness's OOBI from its base URL,
    // publishes the inception event, and collects the witness receipt.
    let (store_dir, keri) = common::temp_keri();
    let alice = keri
        .new_identity("alice")
        .witness(&infra.witness.url)
        .build()
        .await
        .expect("identity creation behind a witness must succeed");

    // The id is a plain string for the outside world.
    let alice_id_text = alice.id().to_string();
    assert!(!alice_id_text.is_empty());

    // The witness we configured is recorded in the identity's key history.
    let witnesses = alice.witnesses().expect("witness lookup");
    assert!(
        witnesses.iter().any(|w| w.starts_with(&infra.witness.url)),
        "expected {} among {witnesses:?}",
        infra.witness.url
    );

    // ── Sign and verify ──────────────────────────────────────────────────
    let signed = alice.sign(b"hello from alice").await.expect("signing");
    // The signed message is a self-contained string — store it, send it.
    let as_text = signed.as_cesr().to_string();

    let verified = keri.verify(&as_text).expect("verification");
    assert_eq!(verified.payload, b"hello from alice");
    assert_eq!(&verified.signer, alice.id());

    // ── Rotate keys ──────────────────────────────────────────────────────
    // Pre-rotation is automatic: the SDK reveals the previously committed
    // next key, commits a fresh one, and gathers witness receipts.
    alice.rotate().await.expect("rotation");

    // Messages signed before the rotation stay verifiable (the key history
    // proves the old key was valid at signing time)…
    let old_again = keri.verify(&as_text).expect("old signature after rotation");
    assert_eq!(old_again.payload, b"hello from alice");

    // …and new messages are signed with the new key.
    let signed_after = alice.sign(b"fresh key, same identity").await.unwrap();
    let verified_after = keri.verify(signed_after.as_cesr()).unwrap();
    assert_eq!(&verified_after.signer, alice.id());

    // ── Restart the application ──────────────────────────────────────────
    // Drop every handle, reopen the same directory, and continue where we
    // left off.
    drop(alice);
    drop(keri);

    let keri = keri_sdk::Keri::open(store_dir.path()).expect("reopen store");
    assert_eq!(keri.identities().unwrap(), vec!["alice"]);

    let alice = keri.identity("alice").expect("load alice after restart");
    assert_eq!(alice.id().to_string(), alice_id_text);

    let signed_later = alice.sign(b"back after restart").await.unwrap();
    let verified_later = keri.verify(signed_later.as_cesr()).unwrap();
    assert_eq!(verified_later.payload, b"back after restart");

    // Another rotation after the restart proves the persisted next-key
    // material survived the round-trip.
    alice.rotate().await.expect("rotation after restart");
}

#[test_context(TestInfra)]
#[actix_rt::test]
async fn two_witnesses_with_threshold(infra: &mut TestInfra) {
    // A second witness for this test only.
    let second = common::spawn_witness();

    let (_store_dir, keri) = common::temp_keri();
    let alice = keri
        .new_identity("alice")
        .witness(&infra.witness.url)
        .witness(&second.url)
        .witness_threshold(2)
        .build()
        .await
        .expect("identity with two witnesses");

    let urls = alice.witnesses().unwrap();
    assert_eq!(urls.len(), 2, "both witnesses recorded: {urls:?}");

    let signed = alice.sign(b"countersigned twice").await.unwrap();
    assert_eq!(
        keri.verify(signed.as_cesr()).unwrap().payload,
        b"countersigned twice"
    );
}
