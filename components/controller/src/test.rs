#![cfg(test)]

use std::sync::Arc;

use keri::{
    actor::prelude::Message,
    derivation::{basic::Basic, self_signing::SelfSigning},
    oobi::LocationScheme,
    prefix::{BasicPrefix, IdentifierPrefix},
    signer::{CryptoBox, KeyManager},
};
use tempfile::Builder;

use super::{error::ControllerError, identifier_controller::IdentifierController, Controller};
use crate::{mailbox_updating::ActionRequired, utils::OptionalConfig};

#[async_std::test]
async fn test_group_incept() -> Result<(), ControllerError> {
    let root = Builder::new().prefix("test-db").tempdir().unwrap();
    let initial_config = OptionalConfig::init().with_db_path(root.into_path());

    let controller = Arc::new(Controller::new(Some(initial_config))?);
    let km1 = CryptoBox::new()?;
    let km2 = CryptoBox::new()?;

    let mut identifier1 = {
        let pk = Basic::Ed25519.derive(km1.public_key());
        let npk = Basic::Ed25519.derive(km1.next_public_key());

        let icp_event = controller.incept(vec![pk], vec![npk], vec![], 0).await?;
        let signature = SelfSigning::Ed25519Sha512.derive(km1.sign(icp_event.as_bytes())?);

        let incepted_identifier = controller
            .finalize_inception(icp_event.as_bytes(), &signature)
            .await?;
        IdentifierController::new(incepted_identifier, controller.clone())
    };

    let identifier2 = {
        let pk = Basic::Ed25519.derive(km2.public_key());
        let npk = Basic::Ed25519.derive(km2.next_public_key());

        let icp_event = controller.incept(vec![pk], vec![npk], vec![], 0).await?;
        let signature = SelfSigning::Ed25519Sha512.derive(km2.sign(icp_event.as_bytes())?);

        let incepted_identifier = controller
            .finalize_inception(icp_event.as_bytes(), &signature)
            .await?;
        IdentifierController::new(incepted_identifier, controller.clone())
    };

    let (group_inception, exn_messages) =
        identifier1.incept_group(vec![identifier2.id.clone()], 2, None, None, None)?;

    let signature_icp = SelfSigning::Ed25519Sha512.derive(km1.sign(group_inception.as_bytes())?);
    let signature_exn = SelfSigning::Ed25519Sha512.derive(km1.sign(exn_messages[0].as_bytes())?);

    // Group initiator needs to use `finalize_group_incept` instead of just
    // `finalize_event`, to send multisig request to other group participants.
    // Identifier who get this request from mailbox, can use just `finalize_event`
    let group_id = identifier1
        .finalize_group_incept(
            group_inception.as_bytes(),
            signature_icp,
            vec![(exn_messages[0].as_bytes(), signature_exn)],
        )
        .await?;

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
    identifier2
        .finalize_event(group_inception.as_bytes(), signature_icp)
        .await?;

    let kel = controller
        .storage
        .get_kel_messages_with_receipts(&group_id)?;
    assert!(kel.is_some());

    Ok(())
}

#[async_std::test]
#[ignore]
async fn test_delegated_incept() -> Result<(), ControllerError> {
    println!("Test start");
    use url::Url;
    let root = Builder::new().prefix("test-db").tempdir().unwrap();
    let root2 = Builder::new().prefix("test-db2").tempdir().unwrap();
    let initial_config = OptionalConfig::init().with_db_path(root.into_path());
    let initial_config2 = OptionalConfig::init().with_db_path(root2.into_path());

    // Tests assumses that witness DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA is listening on http://127.0.0.1:3232
    // It can be run from components/witness using command:
    // cargo run -- -c ./src/witness.json
    // TODO: use fake transport
    let witness_id: IdentifierPrefix = "DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA"
        .parse()
        .unwrap();
    let witness_id_basic: BasicPrefix = "DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA"
        .parse()
        .unwrap();
    let wit_location = LocationScheme {
        eid: witness_id,
        scheme: keri::oobi::Scheme::Http,
        url: Url::parse("http://127.0.0.1:3232").unwrap(),
    };
    println!("Init controllers");
    let controller = Arc::new(Controller::new(Some(initial_config))?);
    let controller2 = Arc::new(Controller::new(Some(initial_config2))?);
    let km1 = CryptoBox::new()?;
    let km2 = CryptoBox::new()?;

    let mut identifier1 = {
        let pk = Basic::Ed25519.derive(km1.public_key());
        let npk = Basic::Ed25519.derive(km1.next_public_key());

        println!("Start incept");
        let icp_event = controller
            .incept(vec![pk], vec![npk], vec![wit_location.clone()], 1)
            .await?;
        let signature = SelfSigning::Ed25519Sha512.derive(km1.sign(icp_event.as_bytes())?);

        println!("Finalize inception");
        let incepted_identifier = controller
            .finalize_inception(icp_event.as_bytes(), &signature)
            .await?;
        IdentifierController::new(incepted_identifier, controller.clone())
    };
    // Quering mailbox to get receipts
    println!("Querying own mailbox to get receipts");
    let query = identifier1.query_own_mailbox(&[witness_id_basic.clone()])?;

    for qry in query {
        let signature = SelfSigning::Ed25519Sha512.derive(km1.sign(&qry.serialize()?)?);
        identifier1
            .finalize_mailbox_query(vec![(qry, signature)])
            .await?;
    }

    let mut delegator = {
        let pk = Basic::Ed25519.derive(km2.public_key());
        let npk = Basic::Ed25519.derive(km2.next_public_key());

        let icp_event = controller2
            .incept(vec![pk], vec![npk], vec![wit_location], 1)
            .await?;
        let signature = SelfSigning::Ed25519Sha512.derive(km2.sign(icp_event.as_bytes())?);

        let incepted_identifier = controller2
            .finalize_inception(icp_event.as_bytes(), &signature)
            .await?;
        IdentifierController::new(incepted_identifier, controller2.clone())
    };

    // Quering mailbox to get receipts
    let query = delegator.query_own_mailbox(&[witness_id_basic.clone()])?;

    for qry in query {
        let signature = SelfSigning::Ed25519Sha512.derive(km2.sign(&qry.serialize()?)?);
        delegator
            .finalize_mailbox_query(vec![(qry, signature)])
            .await?;
    }

    // Generate delegated inception
    let (delegated_inception, exn_messages) = identifier1.incept_group(
        vec![],
        1,
        Some(vec![witness_id_basic.clone()]),
        Some(1),
        Some(delegator.id.clone()),
    )?;

    let signature_icp =
        SelfSigning::Ed25519Sha512.derive(km1.sign(delegated_inception.as_bytes())?);
    let signature_exn = SelfSigning::Ed25519Sha512.derive(km1.sign(exn_messages[0].as_bytes())?);

    // Group initiator needs to use `finalize_group_incept` instead of just
    // `finalize_event`, to send multisig request to other group participants or delegator.
    // Identifier who get this request from mailbox, can use just `finalize_event`
    let delegate_id = identifier1
        .finalize_group_incept(
            delegated_inception.as_bytes(),
            signature_icp.clone(),
            vec![(exn_messages[0].as_bytes(), signature_exn.clone())],
        )
        .await?;

    // Quering mailbox to get receipts
    let query = delegator.query_own_mailbox(&[witness_id_basic.clone()])?;

    for qry in query {
        let signature = SelfSigning::Ed25519Sha512.derive(km2.sign(&qry.serialize()?)?);
        delegator
            .finalize_mailbox_query(vec![(qry, signature)])
            .await?;
    }

    identifier1
        .finalize_exchange(exn_messages[0].as_bytes(), signature_exn, signature_icp)
        .await?;

    println!("before get_kel_messages_with_receipts");
    let kel = controller
        .storage
        .get_kel_messages_with_receipts(&delegate_id)?;
    // Event is not yet accepted. Missing delegating event.
    println!("after get_kel_messages_with_receipts");
    assert!(kel.is_none());

    // Delegator asks about his mailbox to get delegated event.
    let query = delegator.query_own_mailbox(&[witness_id_basic.clone()])?;

    for qry in query {
        let signature = SelfSigning::Ed25519Sha512.derive(km2.sign(&qry.serialize()?)?);
        let ar = delegator
            .finalize_mailbox_query(vec![(qry, signature)])
            .await?;
        assert_eq!(ar.len(), 1);
        match &ar[0] {
            ActionRequired::MultisigRequest(_, _) => unreachable!(),
            ActionRequired::DelegationRequest(delegating_event, exn) => {
                let signature_ixn =
                    SelfSigning::Ed25519Sha512.derive(km2.sign(&delegating_event.serialize()?)?);
                let signature_exn = SelfSigning::Ed25519Sha512.derive(km2.sign(&exn.serialize()?)?);
                delegator
                    .finalize_group_incept(
                        &delegating_event.serialize()?,
                        signature_ixn.clone(),
                        vec![],
                    )
                    .await?;

                // Query for receipts
                let query = delegator.query_own_mailbox(&[witness_id_basic.clone()])?;

                for qry in query {
                    let signature = SelfSigning::Ed25519Sha512.derive(km2.sign(&qry.serialize()?)?);
                    let action_required = delegator
                        .finalize_mailbox_query(vec![(qry, signature)])
                        .await?;
                    assert!(action_required.is_empty());
                }

                delegator
                    .finalize_exchange(&exn.serialize()?, signature_exn, signature_ixn)
                    .await?;

                // ixn was accepted
                let delegators_state = controller2.storage.get_state(&delegator.id)?;
                assert_eq!(delegators_state.unwrap().sn, 1);
            }
        };
    }

    // Process delegator's icp by identifier who'll request delegation.
    // TODO how child should get delegators kel?
    let delegators_kel = controller2
        .storage
        .get_kel_messages_with_receipts(&delegator.id)?
        .unwrap();
    controller.process(&Message::Notice(delegators_kel[0].clone()))?; // icp
    controller.process(&Message::Notice(delegators_kel[1].clone()))?; // receipt

    let query = identifier1.query_group_mailbox(&[witness_id_basic.clone()])?;

    for qry in query {
        let signature = SelfSigning::Ed25519Sha512.derive(km1.sign(&qry.serialize()?)?);
        let ar = identifier1
            .finalize_mailbox_query(vec![(qry, signature)])
            .await?;
        assert!(ar.is_empty());
    }

    let state = identifier1.source.storage.get_state(&delegator.id)?;
    assert_eq!(state.unwrap().sn, 1);

    // Child kel is not yet accepted
    let state = identifier1.source.storage.get_state(&delegate_id)?;
    assert_eq!(state, None);

    // Get mailbox for receipts.
    let query = identifier1.query_group_mailbox(&[witness_id_basic.clone()])?;

    for qry in query {
        let signature = SelfSigning::Ed25519Sha512.derive(km1.sign(&qry.serialize()?)?);
        let ar = identifier1
            .finalize_mailbox_query(vec![(qry, signature)])
            .await?;
        assert!(ar.is_empty());
    }

    // Child kel is accepted
    let state = identifier1.source.storage.get_state(&delegate_id)?;
    assert_eq!(state.unwrap().sn, 0);

    Ok(())
}
