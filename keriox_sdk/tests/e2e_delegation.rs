//! End-to-end: delegation.
//!
//! Alice (a person's main identity) authorizes a new "phone" identity to act
//! under her authority. Three steps, two parties:
//!
//! 1. the phone requests delegation (the request travels through the
//!    shared witness's mailbox),
//! 2. Alice finds the request in `pending_requests()` and approves it,
//! 3. the phone finalizes and becomes a usable delegated identity.

mod common;

use common::TestInfra;
use keri_sdk::PendingRequest;
use test_context::test_context;

#[test_context(TestInfra)]
#[actix_rt::test]
async fn delegate_a_phone_identity(infra: &mut TestInfra) {
    let (store_dir, keri) = common::temp_keri();

    // Alice's main identity.
    let alice = keri
        .new_identity("alice")
        .witness(&infra.witness.url)
        .build()
        .await
        .unwrap();

    // ── Step 1: the phone asks Alice for delegation ──────────────────────
    let handle = keri
        .new_identity("phone")
        .witness(&infra.witness.url)
        .delegated_by(alice.id())
        .build_delegation_request()
        .await
        .expect("delegation request");

    let phone_future_id = handle.delegated_id();
    assert_eq!(&handle.delegator_id(), alice.id());

    // ── Step 2: Alice approves ────────────────────────────────────────────
    let requests = alice.pending_requests().await.expect("mailbox poll");
    let delegation = requests
        .into_iter()
        .find_map(|r| match r {
            PendingRequest::Delegation(d) => Some(d),
            #[allow(unreachable_patterns)]
            _ => None,
        })
        .expect("alice sees the phone's delegation request");
    assert_eq!(delegation.delegate(), phone_future_id);
    delegation.approve().await.expect("approval");

    // ── Step 3: the phone finalizes ───────────────────────────────────────
    let phone = handle.finalize().await.expect("finalize delegation");
    assert_eq!(phone.id(), &phone_future_id);

    // The delegated identity signs; verification works like any other.
    let signed = phone.sign(b"sent from alice's phone").await.unwrap();
    let verified = keri.verify(signed.as_cesr()).unwrap();
    assert_eq!(verified.payload, b"sent from alice's phone");
    assert_eq!(&verified.signer, phone.id());

    // After a restart the delegated identity loads like any other, and no
    // delegation is reported as still in progress.
    drop(phone);
    drop(alice);
    drop(keri);
    let keri = keri_sdk::Keri::open(store_dir.path()).unwrap();
    let phone = keri.identity("phone").expect("delegated identity persists");
    assert_eq!(phone.id(), &phone_future_id);
    assert!(keri.delegation_in_progress("phone").unwrap().is_none());
}

#[test_context(TestInfra)]
#[actix_rt::test]
async fn finalize_before_approval_is_a_clear_error(infra: &mut TestInfra) {
    let (_dir, keri) = common::temp_keri();
    let alice = keri
        .new_identity("alice")
        .witness(&infra.witness.url)
        .build()
        .await
        .unwrap();

    let handle = keri
        .new_identity("tablet")
        .witness(&infra.witness.url)
        .delegated_by(alice.id())
        .build_delegation_request()
        .await
        .unwrap();

    // Nobody approved — finalize must not succeed.
    let result = handle.finalize().await;
    assert!(
        result.is_err(),
        "finalize without approval must fail, got a usable identity"
    );

    // The in-progress handle is recoverable for a later retry.
    let recovered = keri.delegation_in_progress("tablet").unwrap();
    assert!(recovered.is_some());
}
