//! A group identity: two members, either may sign (threshold 1).
//!
//! Needs a running witness (members coordinate through its mailbox):
//!   WITNESS_URL=http://localhost:3232 cargo run -p keri-sdk --example multisig

use std::time::Duration;

use keri_sdk::{Keri, PendingRequest};

#[tokio::main]
async fn main() -> keri_sdk::Result<()> {
    let Ok(witness_url) = std::env::var("WITNESS_URL") else {
        println!("groups need a witness mailbox; set WITNESS_URL=http://... and re-run");
        return Ok(());
    };

    // Alice and Bob run separate applications.
    let (a_dir, b_dir) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let alice_keri = Keri::open(a_dir.path())?;
    let bob_keri = Keri::open(b_dir.path())?;
    let alice = alice_keri.new_identity("alice").witness(&witness_url).build().await?;
    let bob = bob_keri.new_identity("bob").witness(&witness_url).build().await?;

    // They introduce themselves to each other once.
    alice_keri.import_contact(&bob.oobi_url()?).await?;
    bob_keri.import_contact(&alice.oobi_url()?).await?;

    // Alice starts the group and invites Bob.
    let invite = alice.new_group("team").member(bob.id()).threshold(1).initiate().await?;
    println!("group initiated: {}", invite.group_id());

    // Bob accepts the invitation from his mailbox.
    for request in bob.pending_requests().await? {
        if let PendingRequest::Group(group) = request {
            println!("bob sees invitation to {}", group.group_id());
            group.accept_as("team").await?;
        }
    }

    // Alice's side becomes ready once everyone accepted.
    let team = invite.wait_ready(Duration::from_secs(30)).await?;
    println!("group ready, members: {:?}", team.members()?);

    // The group signs; the message verifies against the group's key log.
    let signed = team.sign(b"signed on behalf of the team").await?;
    assert_eq!(alice_keri.verify(signed.as_cesr())?.signer, team.id());

    // The group can also issue credentials from its own registry.
    let cred = team.issue(br#"{"d":"","statement":"team-approved"}"#).await?;
    println!("group credential {} valid: {}", cred.id,
        alice_keri.credential_status(&cred.id).await?.is_valid());
    Ok(())
}
