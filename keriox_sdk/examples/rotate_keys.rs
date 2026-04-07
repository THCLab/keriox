//! Rotate keys for an existing identifier.
//!
//! After rotation the old key is no longer valid for signing. This example
//! shows the full rotation flow including persisting the new key state via
//! `KeriStore::save_rotation`.
//!
//! Rotation requires witnesses to be configured so that the rotation event
//! can be receipted. This example runs offline (no witnesses) for demo
//! purposes and will print an error at the `notify_witnesses` step.

use keri_sdk::{
    operations::rotate,
    types::{IdentifierConfig, RotationConfig},
    BasicPrefix, KeriStore, SeedPrefix,
};
use std::path::PathBuf;

#[tokio::main]
async fn main() -> keri_sdk::Result<()> {
    // ── 1. Create an identifier ───────────────────────────────────────────────

    let tmp = tempfile::tempdir().expect("tempdir");
    let store = KeriStore::open(PathBuf::from(tmp.path()))?;
    let (_identifier, _signer) = store.create("alice", IdentifierConfig::default()).await?;
    println!("Created identifier: {}", _identifier.id());

    // ── 2. Load signer and identifier for rotation ────────────────────────────

    let current_signer = store.load_signer("alice")?;
    let mut identifier = store.load("alice")?;

    // ── 3. Generate a fresh "new next" key ────────────────────────────────────
    //
    // In a real system, generate this from a random seed. Here we use a
    // well-known test seed string for reproducibility.
    let fresh_next_seed: SeedPrefix =
        "ACrmDHtPQjnM8H9pyKA-QBNdfZ-xixTlRZTS8WXCrrMH".parse().unwrap();
    let (fresh_next_pub_key, _) = fresh_next_seed.derive_key_pair()
        .expect("derive key pair");
    let new_next_pk = BasicPrefix::Ed25519NT(fresh_next_pub_key);

    // ── 5. Rotate (requires witnesses in a real deployment) ───────────────────

    let config = RotationConfig {
        new_next_pk,
        witness_to_add: vec![],
        witness_to_remove: vec![],
        witness_threshold: 0,
    };

    match rotate(&mut identifier, current_signer, config).await {
        Ok(()) => {
            println!("Rotation successful");
            // ── 6. Persist the key rotation ───────────────────────────────────
            store.save_rotation("alice", fresh_next_seed)?;
            println!("Key state updated on disk");
        }
        Err(e) => {
            // In offline mode this is expected — no witnesses to notify.
            println!("Rotation error (expected offline): {e}");
        }
    }

    Ok(())
}
