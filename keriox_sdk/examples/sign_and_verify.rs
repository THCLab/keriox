//! Sign and verify a message using a locally-incepted identifier.
//!
//! This example does not require network access — it uses no witnesses or
//! watchers, so everything runs offline.

use keri_sdk::{signing, types::IdentifierConfig, KeriStore};
use std::path::PathBuf;

#[tokio::main]
async fn main() -> keri_sdk::Result<()> {
    // ── 1. Open a store ───────────────────────────────────────────────────────

    let tmp = tempfile::tempdir().expect("tempdir");
    let store = KeriStore::open(PathBuf::from(tmp.path()))?;

    // ── 2. Create an identifier (no witnesses, no watchers) ───────────────────

    let config = IdentifierConfig::default();
    let (identifier, signer) = store.create("alice", config).await?;
    println!("Identifier: {}", identifier.id());

    // ── 3. Sign a message ─────────────────────────────────────────────────────

    let message = b"Hello, KERI!";
    let envelope = signing::sign(&identifier, &signer, message)?;
    println!("Signed CESR envelope ({} bytes)", envelope.cesr.len());

    // ── 4. Verify it ─────────────────────────────────────────────────────────

    let verified = signing::verify(&identifier, envelope.cesr.as_bytes())?;

    assert_eq!(verified.payload, message, "payload mismatch");
    println!("Verified signer: {}", verified.signer_id);
    println!("Payload: {}", String::from_utf8_lossy(&verified.payload));

    Ok(())
}
