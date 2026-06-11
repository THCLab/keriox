//! Delegation: a "phone" identity acting under a main identity's authority.
//!
//! Needs a running witness (the request travels through its mailbox):
//!   WITNESS_URL=http://localhost:3232 cargo run -p keri-sdk --example delegation

use keri_sdk::{Keri, PendingRequest};

#[tokio::main]
async fn main() -> keri_sdk::Result<()> {
    let Ok(witness_url) = std::env::var("WITNESS_URL") else {
        println!("delegation needs a witness mailbox; set WITNESS_URL=http://... and re-run");
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

    // Step 2 — Alice finds the request in her mailbox and approves.
    for request in alice.pending_requests().await? {
        println!("alice sees: {}", request.summary());
        if let PendingRequest::Delegation(approval) = request {
            approval.approve().await?;
            println!("alice approved");
        }
    }

    // Step 3 — the phone finalizes and is ready to use.
    let phone = handle.finalize().await?;
    println!("delegated identity ready: {}", phone.id());

    let signed = phone.sign(b"sent from alice's phone").await?;
    assert_eq!(&keri.verify(signed.as_cesr())?.signer, phone.id());
    println!("phone signs and verifies like any identity — done");
    Ok(())
}
