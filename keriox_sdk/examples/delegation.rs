//! Delegation: a "phone" identity acting under a main identity's authority.
//!
//! Needs a running witness, which witnesses both identities. The request and
//! the approval are messages this example hands over itself; an application
//! delivers them through a messagebox:
//!   WITNESS_URL=http://localhost:3232 cargo run -p keri-sdk --example delegation

use keri_sdk::{Keri, PendingRequest};

#[tokio::main]
async fn main() -> keri_sdk::Result<()> {
    let Ok(witness_url) = std::env::var("WITNESS_URL") else {
        println!("delegation needs a witness; set WITNESS_URL=http://... and re-run");
        return Ok(());
    };

    let dir = tempfile::tempdir().expect("tempdir");
    let keri = Keri::open(dir.path())?;

    // Alice's main identity.
    let alice = keri.new_identity("alice").witness(&witness_url).build().await?;

    // Step 1 — the phone requests delegation from Alice.
    let handle = keri
        .new_identity("phone")
        .witness(&witness_url)
        .delegated_by(alice.id())
        .build_delegation_request()
        .await?;
    println!("requested delegation; future id: {}", handle.delegated_id());

    // Step 2 — Alice receives the request and approves.
    let mut approvals = vec![];
    for message in handle.requests() {
        for request in alice.receive(&message.message).await? {
            println!("alice sees: {}", request.summary());
            if let PendingRequest::Delegation(approval) = request {
                approvals.push(approval.approve().await?);
                println!("alice approved");
            }
        }
    }

    // Step 3 — the phone finalizes with the approval and is ready to use.
    let approval = approvals.pop().expect("alice approved");
    let phone = handle.finalize(&approval.message).await?;
    println!("delegated identity ready: {}", phone.id());

    let signed = phone.sign(b"sent from alice's phone").await?;
    assert_eq!(&keri.verify(signed.as_cesr())?.signer, phone.id());
    println!("phone signs and verifies like any identity — done");
    Ok(())
}
