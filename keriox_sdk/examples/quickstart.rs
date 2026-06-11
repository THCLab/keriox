//! The five-minute tour: create an identity, sign, verify, rotate.
//!
//! Run:  cargo run -p keri-sdk --example quickstart
//! With a witness:  WITNESS_URL=http://localhost:3232 cargo run -p keri-sdk --example quickstart

use keri_sdk::Keri;

#[tokio::main]
async fn main() -> keri_sdk::Result<()> {
    let dir = tempfile::tempdir().expect("tempdir");
    let keri = Keri::open(dir.path())?;

    // A witness countersigns and publishes your key history. Without one,
    // the identity still works — but only this machine can verify it.
    let mut builder = keri.new_identity("alice");
    match std::env::var("WITNESS_URL") {
        Ok(url) => builder = builder.witness(url),
        Err(_) => println!("(no WITNESS_URL set — running locally without a witness)"),
    }
    let alice = builder.build().await?;
    println!("created identity: {}", alice.id());

    // Sign. The result is one self-contained string.
    let signed = alice.sign(b"hello world").await?;
    println!("signed message ({} chars of CESR)", signed.as_cesr().len());

    // Verify — offline, against the locally known key history.
    let verified = keri.verify(signed.as_cesr())?;
    println!(
        "verified: {:?} signed by {}",
        String::from_utf8_lossy(&verified.payload),
        verified.signer
    );

    // Rotate keys. Old signatures stay verifiable.
    alice.rotate().await?;
    println!("rotated keys");
    assert!(keri.verify(signed.as_cesr()).is_ok());

    let again = alice.sign(b"new key, same identity").await?;
    assert_eq!(&keri.verify(again.as_cesr())?.signer, alice.id());
    println!("old and new signatures both verify — done");
    Ok(())
}
