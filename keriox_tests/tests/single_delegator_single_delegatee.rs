use std::sync::Arc;

use keri_controller::{
    config::ControllerConfig, controller::Controller, error::ControllerError,
    mailbox_updating::ActionRequired, BasicPrefix, CryptoBox, KeyManager, SelfSigningPrefix,
};
use keri_core::{actor::prelude::Message, prefix::IndexedSignature};
use keri_tests::settings::InfrastructureContext;
use tempfile::Builder;
use test_context::test_context;

#[test_context(InfrastructureContext)]
#[async_std::test]
async fn single_delegator_single_delegatee(
    ctx: &mut InfrastructureContext,
) -> Result<(), ControllerError> {
    let (first_witness_id, first_witness_oobi) = ctx.first_witness_data();

    // Setup delegator identifier
    let delegator_root = Builder::new().prefix("test-db").tempdir().unwrap();
    let delegator_keypair = CryptoBox::new()?;

    let delegator_pk = BasicPrefix::Ed25519(delegator_keypair.public_key());
    let delegator_npk = BasicPrefix::Ed25519(delegator_keypair.next_public_key());

    let delegatee_root = Builder::new().prefix("test-db2").tempdir().unwrap();

    // Setup delegator identifier
    let delegator_controller = Arc::new(Controller::new(ControllerConfig {
        db_path: delegator_root.path().to_owned(),
        ..Default::default()
    })?);

    let icp_event = delegator_controller
        .incept(
            vec![delegator_pk],
            vec![delegator_npk],
            vec![first_witness_oobi.clone()],
            1,
        )
        .await?;
    let signature = SelfSigningPrefix::Ed25519Sha512(delegator_keypair.sign(icp_event.as_bytes())?);

    let mut delegator_identifier =
        delegator_controller.finalize_incept(icp_event.as_bytes(), &signature)?;
    delegator_identifier.notify_witnesses().await?;

    // Quering mailbox to get receipts
    let query = delegator_identifier
        .query_mailbox(delegator_identifier.id(), &[first_witness_id.clone()])?;

    for qry in query {
        let signature = SelfSigningPrefix::Ed25519Sha512(delegator_keypair.sign(&qry.encode()?)?);
        delegator_identifier
            .finalize_query_mailbox(vec![(qry, signature)])
            .await?;
    }
    println!("Delegator: {}", &delegator_identifier.id());

    // Setup delegatee
    // TODO why we need to setup identifier before incept group to create delegated identifier?
    let delegatee_controller = Arc::new(Controller::new(ControllerConfig {
        db_path: delegatee_root.path().to_owned(),
        ..Default::default()
    })?);

    let delegatee_keypair = CryptoBox::new()?;

    let pk = BasicPrefix::Ed25519(delegatee_keypair.public_key());
    let npk = BasicPrefix::Ed25519(delegatee_keypair.next_public_key());

    let icp_event = delegatee_controller
        .incept(vec![pk], vec![npk], vec![first_witness_oobi.clone()], 1)
        .await?;
    let signature = SelfSigningPrefix::Ed25519Sha512(delegatee_keypair.sign(icp_event.as_bytes())?);

    let mut temporary_delegatee_identifier =
        delegatee_controller.finalize_incept(icp_event.as_bytes(), &signature)?;
    temporary_delegatee_identifier.notify_witnesses().await?;

    // Quering mailbox to get receipts
    let query = temporary_delegatee_identifier.query_mailbox(
        temporary_delegatee_identifier.id(),
        &[first_witness_id.clone()],
    )?;

    for qry in query {
        let signature = SelfSigningPrefix::Ed25519Sha512(delegatee_keypair.sign(&qry.encode()?)?);
        temporary_delegatee_identifier
            .finalize_query_mailbox(vec![(qry, signature)])
            .await?;
    }

    // Generate delegated inception and exn, that is provide delegation request to delegator.
    let (delegated_inception, exn_messages) = temporary_delegatee_identifier.incept_group(
        vec![],
        1,
        Some(1),
        Some(vec![first_witness_id.clone()]),
        Some(1),
        Some(delegator_identifier.id().clone()),
    )?;

    let signature_icp =
        SelfSigningPrefix::Ed25519Sha512(delegatee_keypair.sign(delegated_inception.as_bytes())?);
    let signature_exn =
        SelfSigningPrefix::Ed25519Sha512(delegatee_keypair.sign(exn_messages[0].as_bytes())?);

    let delegatee_id = temporary_delegatee_identifier
        .finalize_group_incept(
            delegated_inception.as_bytes(),
            signature_icp.clone(),
            vec![(exn_messages[0].as_bytes().to_vec(), signature_exn.clone())],
        )
        .await?;

    let kel = delegatee_controller.get_kel_with_receipts(&delegatee_id);
    // Event is not yet accepted. Missing delegating event.
    assert!(kel.is_none());

    // Delegation accept process
    // Delegator asks about his mailbox to get delegated event.
    let query = delegator_identifier
        .query_mailbox(delegator_identifier.id(), &[first_witness_id.clone()])?;

    for qry in query {
        let signature = SelfSigningPrefix::Ed25519Sha512(delegator_keypair.sign(&qry.encode()?)?);
        let ar = delegator_identifier
            .finalize_query_mailbox(vec![(qry, signature)])
            .await?;

        assert_eq!(ar.len(), 1);
        match &ar[0] {
            ActionRequired::MultisigRequest(_, _) => unreachable!(),
            ActionRequired::DelegationRequest(delegating_event, exn) => {
                let signature_ixn = SelfSigningPrefix::Ed25519Sha512(
                    delegator_keypair.sign(&delegating_event.encode()?)?,
                );
                let signature_exn =
                    SelfSigningPrefix::Ed25519Sha512(delegator_keypair.sign(&exn.encode()?)?);
                delegator_identifier
                    .finalize_group_incept(
                        &delegating_event.encode()?,
                        signature_ixn.clone(),
                        vec![],
                    )
                    .await?;
                delegator_identifier.notify_witnesses().await?;

                // Query for receipts
                let query = delegator_identifier
                    .query_mailbox(delegator_identifier.id(), &[first_witness_id.clone()])?;

                for qry in query {
                    let signature =
                        SelfSigningPrefix::Ed25519Sha512(delegator_keypair.sign(&qry.encode()?)?);
                    let action_required = delegator_identifier
                        .finalize_query_mailbox(vec![(qry, signature)])
                        .await?;
                    assert!(action_required.is_empty());
                }
                let data_signature = IndexedSignature::new_both_same(signature_ixn, 0);

                delegator_identifier
                    .finalize_exchange(&exn.encode()?, signature_exn, data_signature)
                    .await?;

                // ixn was accepted
                let delegators_state =
                    delegator_controller.find_state(delegator_identifier.id())?;
                assert_eq!(delegators_state.sn, 1);
            }
        };
    }

    // Process delegator's icp by identifier who'll request delegation.
    // TODO how child should get delegators kel?
    let delegators_kel = delegator_controller
        .get_kel_with_receipts(&delegator_identifier.id())
        .unwrap();
    delegatee_controller
        .known_events
        .save(&Message::Notice(delegators_kel[0].clone()))?; // icp
    delegatee_controller
        .known_events
        .save(&Message::Notice(delegators_kel[1].clone()))?; // receipt

    // Ask about delegated identifier mailbox
    let query =
        temporary_delegatee_identifier.query_mailbox(&delegatee_id, &[first_witness_id.clone()])?;

    for qry in query {
        let signature = SelfSigningPrefix::Ed25519Sha512(delegatee_keypair.sign(&qry.encode()?)?);
        let ar = temporary_delegatee_identifier
            .finalize_query_mailbox(vec![(qry, signature)])
            .await?;
        assert!(ar.is_empty())
    }

    let state = temporary_delegatee_identifier.find_state(delegator_identifier.id())?;
    assert_eq!(state.sn, 1);

    // Child kel is not yet accepted
    let state = temporary_delegatee_identifier.find_state(&delegatee_id);
    // assert_eq!(state, None);
    assert!(state.is_err());

    // Get mailbox for receipts.
    let query =
        temporary_delegatee_identifier.query_mailbox(&delegatee_id, &[first_witness_id.clone()])?;

    for qry in query {
        let signature = SelfSigningPrefix::Ed25519Sha512(delegatee_keypair.sign(&qry.encode()?)?);
        let ar = temporary_delegatee_identifier
            .finalize_query_mailbox(vec![(qry, signature)])
            .await?;
        assert!(ar.is_empty());
    }

    // Child kel is accepted
    let state = temporary_delegatee_identifier.find_state(&delegatee_id)?;
    assert_eq!(state.sn, 0);

    Ok(())
}
