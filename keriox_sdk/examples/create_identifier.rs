//! Create a new KERI identifier with witnesses and watchers.
//!
//! This example requires a running KERI witness (`keria` or `keripy`)
//! and watcher to be reachable. Adjust the OOBI URLs for your environment.

use keri_sdk::{types::IdentifierConfig, KeriStore};
use std::path::PathBuf;

#[tokio::main]
async fn main() -> keri_sdk::Result<()> {
    // ── 1. Open a store ───────────────────────────────────────────────────────

    let store = KeriStore::open(PathBuf::from("/tmp/keri-example"))?;

    // ── 2. Build config ───────────────────────────────────────────────────────
    //
    // In a real scenario, witnesses/watchers are obtained from OOBI resolution.
    // Here we show the structure; replace with real OOBIs for your environment.

    let config = IdentifierConfig {
        // Witnesses are KERI nodes that countersign inception events.
        // Provide their LocationScheme OOBIs here.
        witnesses: vec![
            // Example: LocationScheme from a real witness OOBI URL.
            // "http://witness-host:5631/oobi/BAAAAAAA.../controller/witness"
            //   .parse::<Url>().unwrap()
        ],
        witness_threshold: 0, // require 0 witnesses (offline mode)
        // Watchers observe your KEL and help with key-event discovery.
        watchers: vec![],
    };

    // ── 3. Create the identifier ──────────────────────────────────────────────

    let (identifier, _signer) = store.create("my-did", config).await?;
    println!("Created identifier: {}", identifier.id());

    // ── 4. Reload from disk (demonstrates KeriStore::load) ───────────────────

    let reloaded = store.load("my-did")?;
    assert_eq!(identifier.id(), reloaded.id());
    println!("Reloaded from disk: {}", reloaded.id());

    Ok(())
}
