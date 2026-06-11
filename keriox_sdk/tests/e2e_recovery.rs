//! End-to-end: device loss and recovery.
//!
//! Alice exports a backup of her identity, "loses her device" (a brand-new
//! empty store), restores from the backup, and continues exactly where she
//! left off — old signatures verify, new ones work, key rotation continues.

mod common;

use common::TestInfra;
use test_context::test_context;

#[test_context(TestInfra)]
#[actix_rt::test]
async fn restore_identity_from_backup(infra: &mut TestInfra) {
    // ── Original device ───────────────────────────────────────────────────
    let (_old_dir, old_keri) = common::temp_keri();
    let alice = old_keri
        .new_identity("alice")
        .witness(&infra.witness.url)
        .build()
        .await
        .unwrap();
    let alice_id = alice.id().clone();

    let signed_before = alice.sign(b"signed before the crash").await.unwrap();

    // Take a backup — a plain serializable struct (here via JSON, as an
    // application would store it, encrypted).
    let backup = alice.export().expect("backup");
    let backup_json = serde_json::to_string(&backup).unwrap();

    // The backup identifies its owner without exposing key material in Debug.
    assert_eq!(backup.id().unwrap(), alice_id);
    assert!(!format!("{backup:?}").contains("seed"), "no seeds in Debug");

    // ── Device lost: a completely fresh store ─────────────────────────────
    drop(alice);
    drop(old_keri);
    let (_new_dir, new_keri) = common::temp_keri();

    let backup: keri_sdk::IdentityBackup = serde_json::from_str(&backup_json).unwrap();
    let alice = new_keri
        .new_identity("alice")
        .restore_from(backup)
        .build()
        .await
        .expect("restore");
    assert_eq!(alice.id(), &alice_id);

    // The pre-crash signature verifies in the restored store…
    let verified = new_keri.verify(signed_before.as_cesr()).unwrap();
    assert_eq!(verified.payload, b"signed before the crash");
    assert_eq!(verified.signer, alice_id);

    // …new messages sign and verify…
    let signed_after = alice.sign(b"back from the dead").await.unwrap();
    assert_eq!(
        new_keri.verify(signed_after.as_cesr()).unwrap().payload,
        b"back from the dead"
    );

    // …and the pre-rotation chain is intact: rotation still works.
    alice.rotate().await.expect("rotation after restore");
    let signed_rotated = alice.sign(b"rotated after restore").await.unwrap();
    assert_eq!(
        new_keri.verify(signed_rotated.as_cesr()).unwrap().payload,
        b"rotated after restore"
    );
}
