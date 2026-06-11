//! End-to-end: group identities (multisig).
//!
//! Alice and Bob, in separate stores, form a group identity. The invitation
//! and all co-signing travel through their shared witness's mailbox.

mod common;

use std::time::Duration;

use common::TestInfra;
use keri_sdk::PendingRequest;
use test_context::test_context;

/// Create the two members in separate stores and introduce them to each
/// other (mutual contact import via OOBI URLs).
async fn two_members(
    infra: &TestInfra,
) -> (
    (tempfile::TempDir, keri_sdk::Keri, keri_sdk::Identity),
    (tempfile::TempDir, keri_sdk::Keri, keri_sdk::Identity),
) {
    let (alice_dir, alice_keri) = common::temp_keri();
    let (bob_dir, bob_keri) = common::temp_keri();

    let alice = alice_keri
        .new_identity("alice")
        .witness(&infra.witness.url)
        .build()
        .await
        .unwrap();
    let bob = bob_keri
        .new_identity("bob")
        .witness(&infra.witness.url)
        .build()
        .await
        .unwrap();

    alice_keri
        .import_contact(&bob.oobi_url().unwrap())
        .await
        .unwrap();
    bob_keri
        .import_contact(&alice.oobi_url().unwrap())
        .await
        .unwrap();

    ((alice_dir, alice_keri, alice), (bob_dir, bob_keri, bob))
}

#[test_context(TestInfra)]
#[actix_rt::test]
async fn group_lifecycle_any_member_may_sign(infra: &mut TestInfra) {
    let ((_ad, alice_keri, alice), (_bd, bob_keri, bob)) = two_members(infra).await;

    // ── Alice initiates a group; any single member may sign (threshold 1) ─
    let invite = alice
        .new_group("team")
        .member(bob.id())
        .threshold(1)
        .initiate()
        .await
        .expect("group initiation");
    let group_id = invite.group_id();

    // ── Bob finds the invitation in his mailbox and accepts ───────────────
    let invitation = bob
        .pending_requests()
        .await
        .unwrap()
        .into_iter()
        .find_map(|r| match r {
            PendingRequest::Group(g) if g.is_invitation() => Some(g),
            _ => None,
        })
        .expect("bob sees the group invitation");
    assert_eq!(invitation.group_id(), group_id);
    let team_bob = invitation.accept_as("team").await.expect("accept invite");
    assert_eq!(team_bob.id(), group_id);

    // ── Alice's side becomes ready ────────────────────────────────────────
    let team_alice = invite
        .wait_ready(Duration::from_secs(30))
        .await
        .expect("group ready");
    assert_eq!(team_alice.id(), group_id);
    assert!(team_alice
        .members()
        .unwrap()
        .iter()
        .any(|m| m == bob.id()));

    // ── The group signs; both stores verify ───────────────────────────────
    let signed = team_alice
        .sign(b"signed on behalf of the team")
        .await
        .expect("group signing");
    assert_eq!(signed.signer(), &group_id);

    let verified = alice_keri.verify(signed.as_cesr()).expect("alice verifies");
    assert_eq!(verified.payload, b"signed on behalf of the team");
    assert_eq!(verified.signer, group_id);

    // Bob's store knows the group KEL too (he is a member) — after syncing
    // the co-signatures and receipts from the mailbox.
    team_bob.sync().await.unwrap();
    let verified = bob_keri.verify(signed.as_cesr()).expect("bob verifies");
    assert_eq!(verified.signer, group_id);

    // ── The group issues a credential ─────────────────────────────────────
    let cred = team_alice
        .issue(br#"{"d":"","statement":"team-approved"}"#)
        .await
        .expect("group credential");
    assert_eq!(cred.issuer, group_id);
    assert!(alice_keri
        .credential_status(&cred.id)
        .await
        .unwrap()
        .is_valid());

    // ── Groups reload across restarts ─────────────────────────────────────
    let team_again = alice_keri.group("team").expect("reload group");
    assert_eq!(team_again.id(), group_id);
}

#[test_context(TestInfra)]
#[actix_rt::test]
async fn group_rotation_by_initiator(infra: &mut TestInfra) {
    let ((_ad, _alice_keri, alice), (_bd, _bob_keri, bob)) = two_members(infra).await;

    // Threshold 1: the initiator's signature authorizes group events. The
    // fully co-signed k-of-n rotation (every member approving through the
    // mailbox) is wired via pending_requests()/accept(), but its final
    // signature-merge step is still being stabilized in keri-controller, so
    // this test exercises the initiator-driven rotation end to end.
    let invite = alice
        .new_group("board")
        .member(bob.id())
        .threshold(1)
        .initiate()
        .await
        .unwrap();
    let group_id = invite.group_id();

    let invitation = bob
        .pending_requests()
        .await
        .unwrap()
        .into_iter()
        .find_map(|r| match r {
            PendingRequest::Group(g) if g.is_invitation() => Some(g),
            _ => None,
        })
        .expect("bob sees the invitation");
    let board_bob = invitation.accept_as("board").await.unwrap();

    let board_alice = invite.wait_ready(Duration::from_secs(30)).await.unwrap();
    board_bob.sync().await.unwrap();

    // The group's next keys are the members' pre-committed next keys, so
    // every member rotates their own identity first; the facade refreshes
    // the other members' histories automatically when the rotation starts.
    bob.rotate().await.expect("bob's member rotation");
    board_alice.rotate().await.expect("group rotation");

    // The rotation is on the group's key log, witnessed and final.
    let (alice_member, _) = alice.advanced().unwrap();
    let state = alice_member
        .find_state(group_id.as_prefix())
        .expect("group state after rotation");
    assert_eq!(state.sn, 1, "group KEL advanced to the rotation event");

    // Bob syncs and observes the same rotated state.
    let mut bob_sees_it = false;
    let (bob_member, _) = bob.advanced().unwrap();
    for _ in 0..20 {
        board_bob.sync().await.unwrap();
        if bob_member
            .find_state(group_id.as_prefix())
            .map(|s| s.sn == 1)
            .unwrap_or(false)
        {
            bob_sees_it = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    assert!(bob_sees_it, "bob's store observes the group rotation");
}
