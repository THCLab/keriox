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

/// A credential travels by IPEX: the issuer grants it to its holder, who
/// admits it, and the holder grants it on to a verifier. Each side judges
/// what it is granted from the grant alone and the key histories it knows.
#[test_context(TestInfra)]
#[actix_rt::test]
async fn a_credential_travels_by_ipex(infra: &mut TestInfra) {
    let new_identity = |keri: &keri_sdk::Keri, alias: &'static str| {
        let builder = keri.new_identity(alias).witness(&infra.witness.url);
        async move { builder.build().await.unwrap() }
    };
    let (_issuer_dir, issuer_keri) = common::temp_keri();
    let (_holder_dir, holder_keri) = common::temp_keri();
    let (_verifier_dir, verifier_keri) = common::temp_keri();
    let issuer = new_identity(&issuer_keri, "university").await;
    let holder = new_identity(&holder_keri, "student").await;
    let verifier = new_identity(&verifier_keri, "employer").await;
    let issuer_oobi = issuer.oobi_url().unwrap();
    let holder_oobi = holder.oobi_url().unwrap();

    let diploma = issuer
        .issue(SCHEMA, Block::new().with("degree", "MSc"))
        .await
        .unwrap();

    // Issuer to holder.
    let grant = issuer
        .grant(&diploma.presentation, holder.id(), "Your diploma")
        .unwrap();
    // The holder cannot judge it before knowing the issuer.
    assert!(holder.receive_grant(&grant).is_err());
    holder_keri.import_contact(&issuer_oobi).await.unwrap();
    let received = holder.receive_grant(&grant).unwrap();
    assert_eq!(&received.from, issuer.id());
    assert_eq!(received.status, CredentialStatus::Issued);
    assert_eq!(received.message.as_deref(), Some("Your diploma"));
    assert_eq!(received.acdc.said(), diploma.acdc.said());
    // A grant for someone else is refused.
    assert!(verifier.receive_grant(&grant).is_err());

    let admit = holder.admit(&grant, "Thanks").unwrap();
    issuer_keri.import_contact(&holder_oobi).await.unwrap();
    assert_eq!(&issuer.receive_admit(&admit).unwrap(), holder.id());

    // Holder to verifier.
    let presented = holder
        .grant(&received.presentation, verifier.id(), "My diploma")
        .unwrap();
    verifier_keri.import_contact(&issuer_oobi).await.unwrap();
    verifier_keri.import_contact(&holder_oobi).await.unwrap();
    let checked = verifier.receive_grant(&presented).unwrap();
    assert_eq!(&checked.from, holder.id());
    assert_eq!(checked.status, CredentialStatus::Issued);
}
