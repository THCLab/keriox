//! End-to-end: the credential lifecycle.
//!
//! Issue a credential (the registry is created automatically), check its
//! status, revoke it, and confirm the revocation is visible. Also proves the
//! registry survives an application restart.

mod common;

use common::TestInfra;
use keri_sdk::CredentialStatus;
use test_context::test_context;

#[test_context(TestInfra)]
#[actix_rt::test]
async fn credential_lifecycle(infra: &mut TestInfra) {
    let (store_dir, keri) = common::temp_keri();
    let issuer = keri
        .new_identity("acme")
        .witness(&infra.witness.url)
        .build()
        .await
        .expect("issuer identity");

    // ── Issue ─────────────────────────────────────────────────────────────
    // First issuance also creates the public registry — no separate setup
    // call, no registry id to keep track of.
    let diploma = issuer
        .issue(br#"{"d":"","degree":"MSc Cryptography","holder":"bob"}"#)
        .await
        .expect("issuing first credential");

    // The payload came back with the digest embedded in `d`.
    let payload_text = diploma.payload_str().expect("payload is JSON text");
    assert!(payload_text.contains(&diploma.id.digest()));

    // The credential id is a plain self-contained string.
    let id_text = diploma.id.to_string();
    let parsed: keri_sdk::CredentialId = id_text.parse().unwrap();
    assert_eq!(parsed, diploma.id);

    // ── Status: valid ─────────────────────────────────────────────────────
    let status = keri.credential_status(&diploma.id).await.expect("status");
    assert!(status.is_valid(), "freshly issued credential is valid");

    // ── Revoke ────────────────────────────────────────────────────────────
    issuer.revoke(&diploma.id).await.expect("revocation");
    let status = keri.credential_status(&diploma.id).await.unwrap();
    assert_eq!(status, CredentialStatus::Revoked);
    assert!(!status.is_valid());

    // ── Second issuance reuses the same registry ──────────────────────────
    let badge = issuer
        .issue(b"employee badge #42 (opaque, non-JSON payload)")
        .await
        .expect("second credential");
    assert_eq!(badge.id.registry(), diploma.id.registry());
    assert!(keri.credential_status(&badge.id).await.unwrap().is_valid());

    // Both credentials are in the issuer's index.
    let issued = issuer.credentials().unwrap();
    assert_eq!(issued, vec![diploma.id.clone(), badge.id.clone()]);

    // ── Restart: registry id and statuses survive ─────────────────────────
    drop(issuer);
    drop(keri);
    let keri = keri_sdk::Keri::open(store_dir.path()).unwrap();
    let issuer = keri.identity("acme").unwrap();

    assert_eq!(
        keri.credential_status(&diploma.id).await.unwrap(),
        CredentialStatus::Revoked
    );
    assert!(keri.credential_status(&badge.id).await.unwrap().is_valid());

    // A third credential after restart still lands in the same registry —
    // the registry id was persisted, not re-created.
    let third = issuer.issue(b"third credential").await.unwrap();
    assert_eq!(third.id.registry(), diploma.id.registry());
}

#[test_context(TestInfra)]
#[actix_rt::test]
async fn unknown_credential_reports_unknown(infra: &mut TestInfra) {
    let (_dir, keri) = common::temp_keri();
    keri.new_identity("acme")
        .witness(&infra.witness.url)
        .build()
        .await
        .unwrap();

    // A syntactically valid credential id no registry has ever seen.
    let ghost: keri_sdk::CredentialId =
        "EJe6footPdcb6S7TKnEHEXgB-Ms_iH7krj0Ot4Vcjvr5:ELC5L3iBVD77d_MYbYGGCUQgqQBju1o4x1Ud-z2sL-ux"
            .parse()
            .unwrap();
    assert_eq!(
        keri.credential_status(&ghost).await.unwrap(),
        CredentialStatus::Unknown
    );
}
