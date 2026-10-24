//! A key rotation that does not ask for a new witness threshold keeps the
//! one the identifier already has. Dropping it to zero would let every later
//! event of the identifier stand without a single witness receipt.

mod common;

use common::TestInfra;
use keri_sdk::advanced::{KeriStore, SignatureThreshold, StoreRotationConfig};
use test_context::test_context;

fn witness_tally(store: &KeriStore, alias: &str) -> SignatureThreshold {
    let id = store.load(alias).unwrap();
    id.find_state(id.id()).unwrap().witness_config.tally
}

#[test_context(TestInfra)]
#[actix_rt::test]
async fn a_plain_key_roll_keeps_the_witness_threshold(infra: &mut TestInfra) {
    let (_dir, keri) = common::temp_keri();
    let alice = keri
        .new_identity("alice")
        .witness(&infra.witness.url)
        .build()
        .await
        .unwrap();
    assert_eq!(
        witness_tally(keri.advanced(), "alice"),
        SignatureThreshold::Simple(1)
    );

    alice.rotate().await.expect("rotation");

    assert_eq!(
        witness_tally(keri.advanced(), "alice"),
        SignatureThreshold::Simple(1)
    );
}

#[test_context(TestInfra)]
#[actix_rt::test]
async fn a_rotation_without_a_threshold_keeps_the_current_one(infra: &mut TestInfra) {
    let (_dir, keri) = common::temp_keri();
    keri.new_identity("alice")
        .witness(&infra.witness.url)
        .build()
        .await
        .unwrap();
    let store = keri.advanced();

    store
        .rotate_with(
            "alice",
            StoreRotationConfig {
                new_next_threshold: 1,
                ..Default::default()
            },
        )
        .await
        .expect("rotation");

    assert_eq!(witness_tally(store, "alice"), SignatureThreshold::Simple(1));
}

#[test_context(TestInfra)]
#[actix_rt::test]
async fn a_rotation_with_a_threshold_sets_it(infra: &mut TestInfra) {
    let (_dir, keri) = common::temp_keri();
    keri.new_identity("alice")
        .witness(&infra.witness.url)
        .build()
        .await
        .unwrap();
    let store = keri.advanced();

    store
        .rotate_with(
            "alice",
            StoreRotationConfig {
                witness_threshold: Some(0),
                new_next_threshold: 1,
                ..Default::default()
            },
        )
        .await
        .expect("rotation");

    assert_eq!(witness_tally(store, "alice"), SignatureThreshold::Simple(0));
}
