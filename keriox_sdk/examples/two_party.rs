//! Two applications, two stores: Bob verifies Alice's signature after
//! importing her key history — fully offline in this example.
//!
//! Run:  cargo run -p keri-sdk --example two_party

use keri_sdk::{Error, Keri};

#[tokio::main]
async fn main() -> keri_sdk::Result<()> {
    // Two separate stores — two machines in real life.
    let alice_dir = tempfile::tempdir().expect("tempdir");
    let bob_dir = tempfile::tempdir().expect("tempdir");
    let alice_keri = Keri::open(alice_dir.path())?;
    let bob_keri = Keri::open(bob_dir.path())?;

    let alice = alice_keri.new_identity("alice").build().await?;
    let signed = alice.sign(b"hi bob, it's alice").await?;

    // Bob has never heard of Alice: the error tells him exactly what to do.
    match bob_keri.verify(signed.as_cesr()) {
        Err(Error::UnknownSigner { id }) => {
            println!("bob can't verify yet — unknown signer {id}")
        }
        other => panic!("expected UnknownSigner, got {other:?}"),
    }

    // Alice exports her key history as a string (with a witness she would
    // share alice.oobi_url() instead) and Bob imports it over any channel.
    let alice_history = alice.kel()?;
    let imported = bob_keri.import_contact(&alice_history).await?;
    println!("bob imported contact {imported}");

    // Now the same message verifies.
    let verified = bob_keri.verify(signed.as_cesr())?;
    println!(
        "bob verified: {:?} from {}",
        String::from_utf8_lossy(&verified.payload),
        verified.signer
    );
    Ok(())
}
