//! Issue and check a credential via the TEL.
//!
//! This example requires a running KERI witness because the registry inception
//! event must be anchored and receipted. Run with:
//!
//!   cargo run --example issue_credential
//!
//! The identifier is created with no witnesses for offline demonstration;
//! a real deployment would add witnesses before calling `incept_registry`.

use keri_sdk::{types::IdentifierConfig, KeriStore};
use std::path::PathBuf;

#[tokio::main]
async fn main() -> keri_sdk::Result<()> {
    // ── 1. Create an identifier ───────────────────────────────────────────────

    let tmp = tempfile::tempdir().expect("tempdir");
    let store = KeriStore::open(PathBuf::from(tmp.path()))?;

    // No witnesses — offline demo only. Real deployments need at least one.
    let (identifier, _signer) = store.create("issuer", IdentifierConfig::default()).await?;
    println!("Issuer: {}", identifier.id());

    // ── 2. Incept a credential registry ──────────────────────────────────────
    //
    // Without witnesses, this will fail at the `notify_witnesses` step because
    // there are no witnesses to send to. In a real deployment with witnesses
    // configured this call succeeds and returns the registry identifier.
    //
    // For a fully offline demo we skip this call. Uncomment in real use:
    //
    // let registry_id = incept_registry(&mut identifier, signer.clone()).await?;
    // store.save_registry("issuer", &registry_id)?;

    // ── 3. Issue a credential ─────────────────────────────────────────────────
    //
    // The credential SAID is the Blake3-256 self-addressing identifier of the
    // ACDC body. You compute this outside the SDK using the `acdc` crate.
    //
    // let cred_said: SelfAddressingIdentifier =
    //     "EBdXt3gIXOf2BBWNHdSXCJnFJL5OuQPyM5K0neuniccM".parse().unwrap();
    //
    // issue(&mut identifier, signer.clone(), cred_said.clone()).await?;

    // ── 4. Check credential status ────────────────────────────────────────────
    //
    // Without a registry or witnesses, status is always Unknown locally.
    //
    // In a real deployment after issuing:
    //   let status = check_credential_status(
    //       &identifier, &signer, &registry_id, &cred_said).await?;
    //   assert_eq!(status, CredentialStatus::Issued);

    println!("Example complete (offline mode — no registry or witnesses configured)");

    Ok(())
}
