//! Back an identity up, lose the device, restore, continue.
//!
//! Run:  cargo run -p keri-sdk --example recovery

use keri_sdk::{IdentityBackup, Keri};

#[tokio::main]
async fn main() -> keri_sdk::Result<()> {
    // ── Original device ───────────────────────────────────────────────────
    let old_dir = tempfile::tempdir().expect("tempdir");
    let old_keri = Keri::open(old_dir.path())?;
    let alice = old_keri.new_identity("alice").build().await?;
    let signed = alice.sign(b"signed before the crash").await?;

    // The backup is a plain serializable struct. It contains the signing
    // seeds — a real application encrypts it before writing it anywhere.
    let backup_json = serde_json::to_string(&alice.export()?).expect("serialize");
    println!("backup taken ({} bytes of JSON)", backup_json.len());

    // ── Device lost ───────────────────────────────────────────────────────
    drop(alice);
    drop(old_keri);
    let new_dir = tempfile::tempdir().expect("tempdir");
    let new_keri = Keri::open(new_dir.path())?;

    // ── Restore ───────────────────────────────────────────────────────────
    let backup: IdentityBackup = serde_json::from_str(&backup_json).expect("parse");
    let alice = new_keri
        .new_identity("alice")
        .restore_from(backup)
        .build()
        .await?;
    println!("restored identity {}", alice.id());

    // Old signatures verify; signing and rotation continue working.
    assert!(new_keri.verify(signed.as_cesr()).is_ok());
    alice.rotate().await?;
    let fresh = alice.sign(b"back from the dead").await?;
    assert!(new_keri.verify(fresh.as_cesr()).is_ok());
    println!("pre-crash signature verifies, rotation works — recovery complete");
    Ok(())
}
