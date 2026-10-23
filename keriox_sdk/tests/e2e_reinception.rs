//! Moving an identity to a new identifier (for example from a KERI 1.0 KEL
//! to a KERI 2.0 one): the old identifier is abandoned with a final
//! rotation that anchors the new inception, and contacts that look the old
//! identifier up follow it to the new one without asking.

mod common;

use common::TestInfra;
use keri_core::event_message::keri_version::KeriVersion;
use keri_sdk::{advanced::KeriStore, Keri};
use test_context::test_context;

#[test_context(TestInfra)]
#[actix_rt::test]
async fn a_contact_follows_a_reincepted_identity(infra: &mut TestInfra) {
    let (_alice_dir, alice_keri) = common::temp_keri();
    let alice = alice_keri
        .new_identity("alice")
        .witness(&infra.witness.url)
        .build()
        .await
        .unwrap();
    let old_id = alice.id().clone();

    let (_bob_dir, bob) = common::temp_keri();
    let imported = bob
        .import_contact_from(&old_id, &infra.witness.url)
        .await
        .unwrap();
    assert_eq!(imported, old_id);

    // Alice moves to a new identifier, written in KERI 2.0, with the same
    // witnesses: she reopens her store set to write KERI 2.0.
    let root = alice_keri.advanced().root().to_path_buf();
    drop(alice);
    drop(alice_keri);
    let store = KeriStore::open(root)
        .unwrap()
        .with_keri_version(KeriVersion::V2_0);
    let config = store.same_witnesses("alice").unwrap();
    let (successor, _signer) = store
        .reincept("alice", "alice-2", config)
        .await
        .expect("re-inception");
    assert!(store.load("alice").unwrap().is_abandoned());
    let new_id: keri_sdk::IdentityId = successor.id().to_string().parse().unwrap();
    assert_ne!(new_id, old_id);

    // Bob looks Alice up again and ends up at her new identifier.
    let followed = bob
        .import_contact_from(&old_id, &infra.witness.url)
        .await
        .unwrap();
    assert_eq!(followed, new_id);
    assert_eq!(bob.successor_of(&old_id).unwrap(), Some(new_id.clone()));

    // A message from the new identifier verifies for Bob.
    let alice_2 = Keri::from_store(std::sync::Arc::new(store))
        .identity("alice-2")
        .unwrap();
    let signed = alice_2.sign(b"from my new identifier").await.unwrap();
    assert_eq!(
        bob.verify(signed.as_cesr()).unwrap().payload,
        b"from my new identifier"
    );
}
