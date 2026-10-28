//! End-to-end: the credential lifecycle.
//!
//! An issuer issues a credential (an ACDC with a registry of its own) and
//! revokes it; a verifier in another store judges what is presented to it.
//! Nothing is looked up on the network: the verifier sees the state it is
//! shown, and once it has seen the revocation, an older presentation no
//! longer fools it. The issuer can still revoke after a restart.

mod common;

use common::TestInfra;
use keri_sdk::{acdc::Block, CredentialStatus};
use test_context::test_context;

const SCHEMA: &str = "EOlgQaGgXI6Zqikg4I0KWaQeL9sRUGu7PUj78GekKnSf";

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
    let diploma = issuer
        .issue(SCHEMA, Block::new().with("degree", "MSc Cryptography"))
        .await
        .expect("issuing a credential");
    assert_eq!(diploma.acdc.issuer(), issuer.id().to_string());
    assert_eq!(
        diploma.acdc.registry(),
        Some(diploma.id.registry().as_str())
    );
    let parsed: keri_sdk::CredentialId = diploma.id.to_string().parse().unwrap();
    assert_eq!(parsed, diploma.id);
    assert!(keri
        .verify_credential(&diploma.presentation)
        .unwrap()
        .is_valid());

    // Each credential has a registry of its own.
    let badge = issuer
        .issue(SCHEMA, Block::new().with("badge", 42))
        .await
        .expect("second credential");
    assert_ne!(badge.id.registry(), diploma.id.registry());
    assert_eq!(
        issuer.credentials().unwrap(),
        vec![diploma.id.clone(), badge.id.clone()]
    );

    // ── A verifier elsewhere ──────────────────────────────────────────────
    let (_verifier_dir, verifier) = common::temp_keri();
    verifier
        .new_identity("checker")
        .witness(&infra.witness.url)
        .build()
        .await
        .expect("verifier identity");
    // Not knowing the issuer yet, it cannot decide.
    assert!(matches!(
        verifier.verify_credential(&diploma.presentation).unwrap(),
        CredentialStatus::Indeterminate(_)
    ));
    let oobi = issuer.oobi_url().expect("issuer has a witness");
    verifier.import_contact(&oobi).await.expect("import issuer");
    assert_eq!(
        verifier.verify_credential(&diploma.presentation).unwrap(),
        CredentialStatus::Issued
    );

    // ── Restart, then revoke ──────────────────────────────────────────────
    drop(issuer);
    drop(keri);
    let keri = keri_sdk::Keri::open(store_dir.path()).unwrap();
    let issuer = keri.identity("acme").unwrap();
    let revoked = issuer.revoke(&diploma.id).await.expect("revocation");
    assert_eq!(issuer.presentation(&diploma.id).unwrap(), revoked);
    assert_eq!(
        keri.verify_credential(&revoked).unwrap(),
        CredentialStatus::Revoked
    );

    // The verifier sees the revocation once it is presented and the
    // issuer's key history is refreshed; from then on the older
    // presentation shows the revoked state too.
    verifier
        .import_contact(&oobi)
        .await
        .expect("refresh issuer");
    assert_eq!(
        verifier.verify_credential(&revoked).unwrap(),
        CredentialStatus::Revoked
    );
    assert_eq!(
        verifier.verify_credential(&diploma.presentation).unwrap(),
        CredentialStatus::Revoked
    );
    assert!(verifier
        .verify_credential(&badge.presentation)
        .unwrap()
        .is_valid());
}

/// A presentation altered after issuance is rejected, or refused outright
/// when it no longer reads as one.
#[test_context(TestInfra)]
#[actix_rt::test]
async fn an_altered_presentation_is_refused(infra: &mut TestInfra) {
    let (_dir, keri) = common::temp_keri();
    let issuer = keri
        .new_identity("acme")
        .witness(&infra.witness.url)
        .build()
        .await
        .unwrap();
    let diploma = issuer
        .issue(SCHEMA, Block::new().with("degree", "MSc"))
        .await
        .unwrap();
    let other = issuer
        .issue(SCHEMA, Block::new().with("degree", "PhD"))
        .await
        .unwrap();

    // The credential of one registry presented with the other's registry.
    let acdc = diploma.acdc.raw();
    let mut swapped = acdc.to_vec();
    swapped.extend_from_slice(&other.presentation[other.acdc.raw().len()..]);
    assert!(matches!(
        keri.verify_credential(&swapped).unwrap(),
        CredentialStatus::Rejected(_)
    ));

    let mut truncated = diploma.presentation.clone();
    truncated.pop();
    assert!(keri.verify_credential(&truncated).is_err());
}
