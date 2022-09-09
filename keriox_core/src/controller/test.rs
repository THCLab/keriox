use std::sync::Arc;

use tempfile::Builder;

use crate::{
    controller::utils::OptionalConfig,
    derivation::{basic::Basic, self_signing::SelfSigning},
    event::sections::seal::{EventSeal, Seal},
    event_parsing::{message::key_event_message, EventType},
    signer::{CryptoBox, KeyManager},
};

use super::{error::ControllerError, identifier_controller::IdentifierController, Controller};

#[test]
pub fn test_group_incept() -> Result<(), ControllerError> {
    let root = Builder::new().prefix("test-db").tempdir().unwrap();
    let initial_config = OptionalConfig::init().with_db_path(root.into_path());
    let controller = Arc::new(Controller::new(Some(initial_config))?);
    let km1 = CryptoBox::new()?;
    let km2 = CryptoBox::new()?;

    let mut identifier1 = {
        let pk = Basic::Ed25519.derive(km1.public_key());
        let npk = Basic::Ed25519.derive(km1.next_public_key());

        let icp_event = controller.incept(vec![pk], vec![npk], vec![], 0)?;
        let signature = SelfSigning::Ed25519Sha512.derive(km1.sign(icp_event.as_bytes())?);

        let incepted_identifier =
            controller.finalize_inception(icp_event.as_bytes(), &signature)?;
        IdentifierController::new(incepted_identifier, controller.clone())
    };

    let identifier2 = {
        let pk = Basic::Ed25519.derive(km2.public_key());
        let npk = Basic::Ed25519.derive(km2.next_public_key());

        let icp_event = controller.incept(vec![pk], vec![npk], vec![], 0)?;
        let signature = SelfSigning::Ed25519Sha512.derive(km2.sign(icp_event.as_bytes())?);

        let incepted_identifier =
            controller.finalize_inception(icp_event.as_bytes(), &signature)?;
        IdentifierController::new(incepted_identifier, controller.clone())
    };

    let (group_inception, exn_messages) =
        identifier1.incept_group(vec![identifier2.id.clone()], 2, None, None, None)?;

    let signature_icp = SelfSigning::Ed25519Sha512.derive(km1.sign(group_inception.as_bytes())?);
    let signature_exn = SelfSigning::Ed25519Sha512.derive(km1.sign(exn_messages[0].as_bytes())?);

    // Group initiator needs to use `finalize_group_incept` instead of just
    // `finalize_event`, to send multisig request to other group participants.
    // Identifier who get this request from mailbox, can use just `finalize_event`
    let group_id = identifier1.finalize_group_incept(
        group_inception.as_bytes(),
        signature_icp,
        vec![(exn_messages[0].as_bytes(), signature_exn)],
    )?;

    let kel = controller
        .storage
        .get_kel_messages_with_receipts(&group_id)?;
    // Event is not yet accepted.
    assert!(kel.is_none());

    // TODO: There should be witness who forward group icp from identifier1 to
    // identifier2.  It will be stored in identifier2 mailbox. Assume, that
    // identifier2 found icp signed by identifier1 in his mailbox.
    // It works, because we use common controller for both identifiers.
    let signature_icp = SelfSigning::Ed25519Sha512.derive(km2.sign(group_inception.as_bytes())?);
    identifier2.finalize_event(group_inception.as_bytes(), signature_icp)?;

    let kel = controller
        .storage
        .get_kel_messages_with_receipts(&group_id)?;
    assert!(kel.is_some());

    Ok(())
}

#[test]
pub fn test_delegated_incept() -> Result<(), ControllerError> {
    let root = Builder::new().prefix("test-db").tempdir().unwrap();
    let initial_config = OptionalConfig::init().with_db_path(root.into_path());
    let controller = Arc::new(Controller::new(Some(initial_config))?);
    let km1 = CryptoBox::new()?;
    let km2 = CryptoBox::new()?;

    let mut identifier1 = {
        let pk = Basic::Ed25519.derive(km1.public_key());
        let npk = Basic::Ed25519.derive(km1.next_public_key());

        let icp_event = controller.incept(vec![pk], vec![npk], vec![], 0)?;
        let signature = SelfSigning::Ed25519Sha512.derive(km1.sign(icp_event.as_bytes())?);

        let incepted_identifier =
            controller.finalize_inception(icp_event.as_bytes(), &signature)?;
        IdentifierController::new(incepted_identifier, controller.clone())
    };

    let delegator = {
        let pk = Basic::Ed25519.derive(km2.public_key());
        let npk = Basic::Ed25519.derive(km2.next_public_key());

        let icp_event = controller.incept(vec![pk], vec![npk], vec![], 0)?;
        let signature = SelfSigning::Ed25519Sha512.derive(km2.sign(icp_event.as_bytes())?);

        let incepted_identifier =
            controller.finalize_inception(icp_event.as_bytes(), &signature)?;
        IdentifierController::new(incepted_identifier, controller.clone())
    };

    let (delegated_inception, exn_messages) =
        identifier1.incept_group(vec![], 1, None, None, Some(delegator.id.clone()))?;

    let signature_icp =
        SelfSigning::Ed25519Sha512.derive(km1.sign(delegated_inception.as_bytes())?);
    let signature_exn = SelfSigning::Ed25519Sha512.derive(km1.sign(exn_messages[0].as_bytes())?);

    // Group initiator needs to use `finalize_group_incept` instead of just
    // `finalize_event`, to send multisig request to other group participants.
    // Identifier who get this request from mailbox, can use just `finalize_event`
    let delegate_id = identifier1.finalize_group_incept(
        delegated_inception.as_bytes(),
        signature_icp,
        vec![(exn_messages[0].as_bytes(), signature_exn)],
    )?;

    let kel = controller
        .storage
        .get_kel_messages_with_receipts(&delegate_id)?;
    // Event is not yet accepted.
    assert!(kel.is_none());

    // TODO: There should be witness who forward group icp from identifier1 to
    // delegator. It will be stored in delegators mailbox. Assume, that
    // delegator found dip signed by identifier1 in his mailbox.
    // It works, because we use common controller for both identifiers.
    let (_, deserialized_icp) = key_event_message(delegated_inception.as_bytes()).unwrap();
    let delegated_seal = if let EventType::KeyEvent(dip) = deserialized_icp {
        let id = dip.event.get_prefix();
        let event_digest = dip.get_digest();
        let sn = 0;
        Seal::Event(EventSeal {
            prefix: id,
            sn,
            event_digest,
        })
    } else {
        unreachable!()
    };

    let ixn = delegator.anchor_with_seal(&[delegated_seal])?;
    let signature_ixn = SelfSigning::Ed25519Sha512.derive(km2.sign(&ixn.serialize()?)?);
    delegator.finalize_event(&ixn.serialize()?, signature_ixn)?;

    let kel = controller
        .storage
        .get_kel_messages_with_receipts(&delegate_id)?;

    assert!(kel.is_some());

    Ok(())
}
