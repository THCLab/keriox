//! End-to-end: two independent parties.
//!
//! Alice and Bob run separate applications with separate stores. Bob cannot
//! verify Alice's signature until he imports her identity — either via her
//! OOBI URL (fetched from her witness) or her raw key history (offline).

mod common;

use common::TestInfra;
use keri_sdk::Error;
use test_context::test_context;

#[test_context(TestInfra)]
#[actix_rt::test]
async fn verify_a_stranger_then_a_contact(infra: &mut TestInfra) {
    // Two completely separate stores — different machines in real life.
    let (_alice_dir, alice_keri) = common::temp_keri();
    let (_bob_dir, bob_keri) = common::temp_keri();

    let alice = alice_keri
        .new_identity("alice")
        .witness(&infra.witness.url)
        .build()
        .await
        .unwrap();

    let signed = alice.sign(b"hi bob, it's alice").await.unwrap();

    // At this point Bob has never heard of Alice: verification refuses with
    // a typed error telling him what to do about it.
    let err = bob_keri.verify(signed.as_cesr()).unwrap_err();
    assert!(
        matches!(&err, Error::UnknownSigner { id } if id == alice.id()),
        "expected UnknownSigner, got: {err}"
    );

    // Alice shares her OOBI URL (a plain string she gets from the SDK).
    let oobi_url = alice.oobi_url().expect("alice has a witness");
    assert!(oobi_url.contains(&alice.id().to_string()));

    // Bob imports her — the SDK fetches her key history from the witness.
    let imported = bob_keri.import_contact(&oobi_url).await.expect("import");
    assert_eq!(&imported, alice.id());

    // Now the same message verifies.
    let verified = bob_keri.verify(signed.as_cesr()).unwrap();
    assert_eq!(verified.payload, b"hi bob, it's alice");
    assert_eq!(&verified.signer, alice.id());

    // Alice rotates her keys and signs again. Bob re-imports to pick up the
    // rotation, then verifies both old and new messages.
    alice.rotate().await.unwrap();
    let signed_after = alice.sign(b"new keys, still alice").await.unwrap();

    bob_keri.import_contact(&oobi_url).await.expect("refresh");
    assert_eq!(
        bob_keri.verify(signed_after.as_cesr()).unwrap().payload,
        b"new keys, still alice"
    );
    assert_eq!(
        bob_keri.verify(signed.as_cesr()).unwrap().payload,
        b"hi bob, it's alice"
    );
}

#[test_context(TestInfra)]
#[actix_rt::test]
async fn offline_import_via_key_history(infra: &mut TestInfra) {
    let (_alice_dir, alice_keri) = common::temp_keri();
    let (_bob_dir, bob_keri) = common::temp_keri();

    let alice = alice_keri
        .new_identity("alice")
        .witness(&infra.witness.url)
        .build()
        .await
        .unwrap();
    let signed = alice.sign(b"sent on a USB stick").await.unwrap();

    // No URL exchanged: Alice exports her key history as a string and Bob
    // ingests it directly — works fully offline.
    let kel = alice.kel().expect("own key history");
    let imported = bob_keri.import_contact(&kel).await.expect("offline import");
    assert_eq!(&imported, alice.id());

    let verified = bob_keri.verify(signed.as_cesr()).unwrap();
    assert_eq!(verified.payload, b"sent on a USB stick");
}

#[test_context(TestInfra)]
#[actix_rt::test]
async fn tampered_message_is_rejected(infra: &mut TestInfra) {
    let (_alice_dir, alice_keri) = common::temp_keri();
    let (_bob_dir, bob_keri) = common::temp_keri();

    let alice = alice_keri
        .new_identity("alice")
        .witness(&infra.witness.url)
        .build()
        .await
        .unwrap();
    bob_keri.import_contact(&alice.kel().unwrap()).await.unwrap();

    let signed = alice.sign(b"pay 10 to carol").await.unwrap();

    // Flip the amount inside the signed payload.
    let tampered = signed.as_cesr().replace("pay 10", "pay 99");
    assert_ne!(tampered, signed.as_cesr(), "payload must actually change");

    let err = bob_keri.verify(&tampered).unwrap_err();
    assert!(
        matches!(err, Error::InvalidSignature { .. }),
        "expected InvalidSignature, got: {err}"
    );
}
