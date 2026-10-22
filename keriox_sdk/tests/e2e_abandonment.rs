//! End-to-end: ending an identity for good (KERI abandonment).
//!
//! An abandoned identity's key history is final. Its witnesses refuse
//! anything after the abandonment, everyone who looks it up sees it as
//! abandoned, and signatures made with its final keys are refused, while
//! messages it signed before stay verifiable. Afterwards its keys and local
//! data can be removed.

mod common;

use common::TestInfra;
use keri_sdk::advanced::{fetch_identifier_status, supports_abandonment, IdentifierPrefix};
use keri_sdk::Error;
use test_context::test_context;
use url::Url;

fn prefix(id: &keri_sdk::IdentityId) -> IdentifierPrefix {
    id.to_string().parse().unwrap()
}

#[test_context(TestInfra)]
#[actix_rt::test]
async fn an_abandoned_identity_is_final_and_can_be_removed(infra: &mut TestInfra) {
    let witness = Url::parse(&infra.witness.url).unwrap();
    let watcher = Url::parse(&infra.watcher.url).unwrap();
    // The infrastructure enforces abandonment, so it is safe to abandon.
    assert!(supports_abandonment(&witness).await.unwrap());
    assert!(supports_abandonment(&watcher).await.unwrap());

    let (store_dir, keri) = common::temp_keri();
    let alice = keri
        .new_identity("alice")
        .witness(&infra.witness.url)
        .build()
        .await
        .unwrap();
    let before = alice.sign(b"signed while alive").await.unwrap();
    assert!(!alice.is_abandoned().unwrap());

    alice.abandon().await.expect("abandonment");
    assert!(alice.is_abandoned().unwrap());

    // Nothing more in its name.
    assert!(matches!(
        alice.sign(b"after the end").await,
        Err(Error::Abandoned { id }) if &id == alice.id()
    ));
    assert!(matches!(alice.rotate().await, Err(Error::Abandoned { .. })));
    assert!(matches!(
        alice.abandon().await,
        Err(Error::Abandoned { .. })
    ));

    // Messages signed before stay verifiable, but anything signed with the
    // final keys (which can never be rotated away) is refused.
    let verified = keri.verify(before.as_cesr()).unwrap();
    assert_eq!(verified.payload, b"signed while alive");
    let store = keri.advanced();
    let final_keys = store.load_signer("alice").unwrap();
    let forged = keri_sdk::advanced::signing::sign(
        &store.load("alice").unwrap(),
        &final_keys,
        b"signed with the final keys",
    )
    .unwrap();
    assert!(matches!(
        keri.verify(&forged.cesr),
        Err(Error::Abandoned { id }) if &id == alice.id()
    ));

    // The witness reports it publicly.
    let status = fetch_identifier_status(&witness, &prefix(alice.id()))
        .await
        .unwrap()
        .expect("the witness knows alice");
    let abandonment = status.abandoned.expect("reported as abandoned");
    assert_eq!(abandonment.sn, 1);
    assert_eq!(status.sn, 1);
    let unknown: IdentifierPrefix = "BJq7UABlttINuWJh1Xl2lkqZG4NTdUdqnbFJDa6ZyxCC"
        .parse()
        .unwrap();
    assert!(fetch_identifier_status(&witness, &unknown)
        .await
        .unwrap()
        .is_none());

    // Remove the keys and local data: nothing of alice is left behind.
    keri.remove_identity("alice").unwrap();
    assert!(keri.identities().unwrap().is_empty());
    assert!(matches!(
        keri.identity("alice"),
        Err(Error::IdentityNotFound(_))
    ));
    assert!(!store_dir.path().join("alice").exists());
    assert_eq!(store.read_meta("alice", "priv_key").unwrap(), None);
    assert_eq!(store.read_meta("alice", "id").unwrap(), None);
    assert!(matches!(
        keri.remove_identity("alice"),
        Err(Error::IdentityNotFound(_))
    ));
}

#[test_context(TestInfra)]
#[actix_rt::test]
async fn removing_an_identity_leaves_the_others(infra: &mut TestInfra) {
    let (_store_dir, keri) = common::temp_keri();
    for alias in ["alice", "bob"] {
        keri.new_identity(alias)
            .witness(&infra.witness.url)
            .build()
            .await
            .unwrap();
    }

    keri.remove_identity("alice").unwrap();

    assert_eq!(keri.identities().unwrap(), vec!["bob"]);
    let bob = keri.identity("bob").unwrap();
    let signed = bob.sign(b"still here").await.unwrap();
    assert_eq!(
        keri.verify(signed.as_cesr()).unwrap().payload,
        b"still here"
    );
}

#[test_context(TestInfra)]
#[actix_rt::test]
async fn a_delegated_identity_is_abandoned_once_its_delegator_approves(infra: &mut TestInfra) {
    let (_store_dir, keri) = common::temp_keri();
    let alice = keri
        .new_identity("alice")
        .witness(&infra.witness.url)
        .build()
        .await
        .unwrap();
    let handle = keri
        .new_identity("phone")
        .witness(&infra.witness.url)
        .delegated_by(alice.id())
        .build_delegation_request()
        .await
        .unwrap();
    approve_delegation(&alice).await;
    let phone = handle.finalize().await.unwrap();

    // The phone's abandonment is a delegated rotation: it waits for Alice.
    assert!(matches!(
        phone.abandon().await,
        Err(Error::PendingApproval { .. })
    ));
    assert!(!phone.is_abandoned().unwrap());
    assert!(matches!(
        phone.abandon().await,
        Err(Error::PendingApproval { .. })
    ));

    approve_delegation(&alice).await;
    phone.abandon().await.expect("approved abandonment");
    assert!(phone.is_abandoned().unwrap());
    let status = fetch_identifier_status(
        &Url::parse(&infra.witness.url).unwrap(),
        &prefix(phone.id()),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(status.abandoned.unwrap().sn, 1);

    // Then Alice ends her own identity.
    alice.abandon().await.unwrap();
    assert!(alice.is_abandoned().unwrap());
}

async fn approve_delegation(delegator: &keri_sdk::Identity) {
    let request = delegator
        .pending_requests()
        .await
        .unwrap()
        .into_iter()
        .find_map(|r| match r {
            keri_sdk::PendingRequest::Delegation(d) => Some(d),
            #[allow(unreachable_patterns)]
            _ => None,
        })
        .expect("a pending delegation request");
    request.approve().await.unwrap();
}

/// Key providers block on their own runtime, so this runs on a
/// multi-threaded one, with no witnesses.
#[cfg(feature = "keyprovider")]
#[tokio::test(flavor = "multi_thread")]
async fn a_provider_backed_identity_is_abandoned_by_its_next_key() {
    use std::sync::Arc;

    use keri_keyprovider::{software::SoftwareKeyProvider, KeyProvider, SignatureAlgorithm};

    let provider = |label: &str| -> Arc<dyn KeyProvider> {
        Arc::new(SoftwareKeyProvider::generate(label, SignatureAlgorithm::Ed25519).unwrap())
    };
    let (_store_dir, keri) = common::temp_keri();
    let mut device = keri
        .new_identity("device")
        .key_providers(provider("current"), provider("next"))
        .build()
        .await
        .unwrap();
    let before = device.sign(b"signed while alive").await.unwrap();

    assert!(matches!(
        device.abandon().await,
        Err(Error::InvalidInput { .. })
    ));
    device.abandon_with_provider().await.unwrap();

    assert!(device.is_abandoned().unwrap());
    assert!(matches!(
        device.sign(b"after the end").await,
        Err(Error::Abandoned { .. })
    ));
    assert!(keri.verify(before.as_cesr()).is_ok());
}
