//! Issue a revocable credential, check its status, revoke it.
//!
//! Run:  cargo run -p keri-sdk --example credentials
//! (set WITNESS_URL=http://... to run against a real witness)

use keri_sdk::Keri;

#[tokio::main]
async fn main() -> keri_sdk::Result<()> {
    let dir = tempfile::tempdir().expect("tempdir");
    let keri = Keri::open(dir.path())?;

    let mut builder = keri.new_identity("acme-university");
    if let Ok(url) = std::env::var("WITNESS_URL") {
        builder = builder.witness(url);
    }
    let issuer = builder.build().await?;

    // First issuance creates the public registry automatically. A JSON
    // payload with a `d` field gets the credential's digest embedded.
    let diploma = issuer
        .issue(br#"{"d":"","degree":"MSc Cryptography","holder":"bob"}"#)
        .await?;
    println!("issued credential: {}", diploma.id);
    println!("payload with embedded digest: {}", diploma.payload_str().unwrap());

    // Anyone holding the credential id (a plain string) can check it.
    let status = keri.credential_status(&diploma.id).await?;
    println!("status: {status:?} (valid: {})", status.is_valid());

    // Revocation is one call by the issuer, visible to every checker.
    issuer.revoke(&diploma.id).await?;
    let status = keri.credential_status(&diploma.id).await?;
    println!("after revocation: {status:?} (valid: {})", status.is_valid());

    // The issuer's index remembers everything it issued.
    let issued: Vec<String> = issuer.credentials()?.iter().map(|c| c.to_string()).collect();
    println!("issued so far: {issued:?}");
    Ok(())
}
