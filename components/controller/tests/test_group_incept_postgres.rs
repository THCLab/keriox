mod common;

use std::sync::Arc;

use keri_controller::{
    config::ControllerConfig, controller::PostgresController, error::ControllerError,
};
use keri_core::{
    prefix::{BasicPrefix, SelfSigningPrefix},
    signer::{CryptoBox, KeyManager},
};
use tempfile::Builder;

#[async_std::test]
async fn test_group_incept_postgres() -> Result<(), ControllerError> {
    common::ensure_clean_db();

    let root = Builder::new().prefix("test-db").tempdir().unwrap();
    let controller = Arc::new(
        PostgresController::new_postgres(
            &common::get_database_url(),
            ControllerConfig {
                db_path: root.path().to_owned(),
                ..Default::default()
            },
        )
        .await?,
    );

    let km1 = CryptoBox::new()?;
    let km2 = CryptoBox::new()?;

    let pk = BasicPrefix::Ed25519(km1.public_key());
    let npk = BasicPrefix::Ed25519(km1.next_public_key());

    let icp_event = controller.incept(vec![pk], vec![npk], vec![], 0).await?;
    let signature = SelfSigningPrefix::Ed25519Sha512(km1.sign(icp_event.as_bytes())?);
    let mut identifier1 = controller.finalize_incept(icp_event.as_bytes(), &signature)?;

    let pk = BasicPrefix::Ed25519(km2.public_key());
    let npk = BasicPrefix::Ed25519(km2.next_public_key());

    let icp_event = controller.incept(vec![pk], vec![npk], vec![], 0).await?;
    let signature = SelfSigningPrefix::Ed25519Sha512(km2.sign(icp_event.as_bytes())?);
    let mut identifier2 = controller.finalize_incept(icp_event.as_bytes(), &signature)?;

    let (group_inception, exn_messages) =
        identifier1.incept_group(vec![identifier2.id().clone()], 2, Some(2), None, None, None)?;

    let signature_icp = SelfSigningPrefix::Ed25519Sha512(km1.sign(group_inception.as_bytes())?);
    let signature_exn = SelfSigningPrefix::Ed25519Sha512(km1.sign(exn_messages[0].as_bytes())?);
    let exn_index_signature = identifier1.sign_with_index(signature_exn, 0)?;

    // Group initiator uses `finalize_group_incept` to send multisig request to other participants.
    let group_id = identifier1
        .finalize_group_incept(
            group_inception.as_bytes(),
            signature_icp,
            vec![(exn_messages[0].as_bytes().to_vec(), exn_index_signature)],
        )
        .await?;

    let kel = controller.get_kel_with_receipts(&group_id);
    // Event is not yet accepted — needs both signatures.
    assert!(kel.is_none());

    // identifier2 receives the group icp from identifier1's mailbox (shared controller).
    let signature_icp = SelfSigningPrefix::Ed25519Sha512(km2.sign(group_inception.as_bytes())?);
    identifier2
        .finalize_group_event(group_inception.as_bytes(), signature_icp, vec![])
        .await?;

    let kel = controller.get_kel_with_receipts(&group_id);
    assert!(kel.is_some());

    Ok(())
}
