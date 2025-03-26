use std::sync::Arc;

use keri_controller::{config::ControllerConfig, controller::Controller, error::ControllerError};
use keri_core::{
    prefix::{BasicPrefix, SelfSigningPrefix},
    signer::{CryptoBox, KeyManager},
};
use tempfile::Builder;

#[async_std::test]
async fn test_group_incept() -> Result<(), ControllerError> {
    let root = Builder::new().prefix("test-db").tempdir().unwrap();

    let controller = Arc::new(Controller::new(ControllerConfig {
        db_path: root.path().to_owned(),
        ..Default::default()
    })?);
    let km1 = CryptoBox::new()?;
    let km2 = CryptoBox::new()?;

    let pk = BasicPrefix::Ed25519(km1.public_key());
    let npk = BasicPrefix::Ed25519(km1.next_public_key());

    let icp_event = controller.incept(vec![pk], vec![npk], vec![], 0).await?;
    let signature = SelfSigningPrefix::Ed25519Sha512(km1.sign(icp_event.as_bytes())?);

    let mut identifier1 = controller.finalize_incept(icp_event.as_bytes(), &signature)?;

    // identifier1.notify_witnesses().await?;

    let pk = BasicPrefix::Ed25519(km2.public_key());
    let npk = BasicPrefix::Ed25519(km2.next_public_key());

    let icp_event = controller.incept(vec![pk], vec![npk], vec![], 0).await?;
    let signature = SelfSigningPrefix::Ed25519Sha512(km2.sign(icp_event.as_bytes())?);

    let mut identifier2 = controller.finalize_incept(icp_event.as_bytes(), &signature)?;
    // identifier2.notify_witnesses().await?;

    let (group_inception, exn_messages) =
        identifier1.incept_group(vec![identifier2.id().clone()], 2, Some(2), None, None, None)?;

    let signature_icp = SelfSigningPrefix::Ed25519Sha512(km1.sign(group_inception.as_bytes())?);
    let signature_exn = SelfSigningPrefix::Ed25519Sha512(km1.sign(exn_messages[0].as_bytes())?);

    // Group initiator needs to use `finalize_group_incept` instead of just
    // `finalize_event`, to send multisig request to other group participants.
    // Identifier who get this request from mailbox, can use just `finalize_event`
    let group_id = identifier1
        .finalize_group_incept(
            group_inception.as_bytes(),
            signature_icp,
            vec![(exn_messages[0].as_bytes().to_vec(), signature_exn)],
        )
        .await?;

    let kel = controller.get_kel_with_receipts(&group_id);
    // Event is not yet accepted.
    assert!(kel.is_none());

    // TODO: There should be witness who forward group icp from identifier1 to
    // identifier2.  It will be stored in identifier2 mailbox. Assume, that
    // identifier2 found icp signed by identifier1 in his mailbox.
    // It works, because we use common controller for both identifiers.
    let signature_icp = SelfSigningPrefix::Ed25519Sha512(km2.sign(group_inception.as_bytes())?);
    identifier2
        .finalize_group_incept(group_inception.as_bytes(), signature_icp, vec![])
        .await?;

    let kel = controller.get_kel_with_receipts(&group_id);
    assert!(kel.is_some());

    Ok(())
}
