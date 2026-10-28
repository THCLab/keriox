//! Issue a revocable credential, verify what the holder presents, revoke it.
//!
//! Run:  cargo run -p keri-sdk --example credentials
//! (set WITNESS_URL=http://... to run against a real witness)

use keri_sdk::{acdc::Block, Keri};

#[tokio::main]
async fn main() -> keri_sdk::Result<()> {
    let dir = tempfile::tempdir().expect("tempdir");
    let keri = Keri::open(dir.path())?;

    let mut builder = keri.new_identity("acme-university");
    if let Ok(url) = std::env::var("WITNESS_URL") {
        builder = builder.witness(url);
    }
    let issuer = builder.build().await?;

    // A credential is an ACDC of some schema, here named by its SAID, with
    // a registry of its own that records its state.
    let schema = "EOlgQaGgXI6Zqikg4I0KWaQeL9sRUGu7PUj78GekKnSf";
    let diploma = issuer
        .issue(schema, Block::new().with("degree", "MSc Cryptography"))
        .await?;
    println!("issued credential: {}", diploma.id);

    // The holder gets the presentation and shows it to verifiers, who check
    // it against the issuer's key history.
    let status = keri.verify_credential(&diploma.presentation)?;
    println!("status: {status:?} (valid: {})", status.is_valid());

    // Revoking gives the revoked presentation: verifiers see the revocation
    // once it is presented to them.
    let revoked = issuer.revoke(&diploma.id).await?;
    let status = keri.verify_credential(&revoked)?;
    println!(
        "after revocation: {status:?} (valid: {})",
        status.is_valid()
    );

    let issued: Vec<String> = issuer
        .credentials()?
        .iter()
        .map(|c| c.to_string())
        .collect();
    println!("issued so far: {issued:?}");
    Ok(())
}
