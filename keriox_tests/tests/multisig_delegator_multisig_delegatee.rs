use keri_controller::{
    error::ControllerError, mailbox_updating::ActionRequired, KeyManager, SelfSigningPrefix,
};
use keri_core::actor::prelude::Message;
use keri_tests::{handle_delegation_request, settings::InfrastructureContext, setup_identifier};
use tempfile::Builder;
use test_context::test_context;

#[test_context(InfrastructureContext)]
#[async_std::test]
async fn multi_delegator_multi_delegatee(
    ctx: &mut InfrastructureContext,
) -> Result<(), ControllerError> {
    let (witness_id, witness_oobi) = ctx.first_witness_data();

    // Setup delegator identifier. It will be multisig group.
    // Setup identifier for first group participant.
    let root_0 = Builder::new().prefix("test-db1").tempdir().unwrap();
    let (mut delegator_identifier1, delegator_km1, controller1) =
        setup_identifier(root_0.path(), vec![witness_oobi.clone()], None, None).await;

    assert!(delegator_identifier1.get_own_kel().is_some());

    // Setup identifier for second group participant.
    let root_1 = Builder::new().prefix("test-db2").tempdir().unwrap();
    let (mut delegator_identifier2, delegator_km2, controller2) =
        setup_identifier(root_1.path(), vec![witness_oobi.clone()], None, None).await;

    assert!(delegator_identifier2.get_own_kel().is_some());

    // Provide second identifier's KEL to first identifier. Can be done by watcher. Is necessary to create multisig event.
    let id2_kel = delegator_identifier2.get_own_kel().unwrap();
    for msg in id2_kel {
        delegator_identifier1
            .known_events
            .process(&Message::Notice(msg))
            .unwrap();
    }

    let state = delegator_identifier1
        .find_state(delegator_identifier2.id())
        .unwrap();
    assert_eq!(state.sn, 0);

    // Provide first identifier's KEL to second identifier. Can be done by watcher.
    let id1_kel = delegator_identifier1.get_own_kel().unwrap();
    for msg in id1_kel {
        delegator_identifier2
            .known_events
            .process(&Message::Notice(msg))
            .unwrap();
    }

    let state = delegator_identifier2
        .find_state(delegator_identifier1.id())
        .unwrap();
    assert_eq!(state.sn, 0);

    // Identifier 1 initiate group inception
    let (group_inception, exn_messages) = delegator_identifier1.incept_group(
        vec![delegator_identifier2.id().clone()],
        2,
        Some(2),
        Some(vec![witness_id.clone()]),
        Some(1),
        None,
    )?;

    let signature_icp =
        SelfSigningPrefix::Ed25519Sha512(delegator_km1.sign(group_inception.as_bytes())?);
    let signature_exn =
        SelfSigningPrefix::Ed25519Sha512(delegator_km1.sign(exn_messages[0].as_bytes())?);

    // Group initiator needs to use `finalize_group_incept` instead of just
    // `finalize_event`, to send multisig request to other group participants.
    // Identifier who get this request from mailbox, can use just `finalize_event`
    let delegator_group_id = delegator_identifier1
        .finalize_group_incept(
            group_inception.as_bytes(),
            signature_icp,
            vec![(exn_messages[0].as_bytes().to_vec(), signature_exn)],
        )
        .await?;

    let kel = delegator_identifier1.get_kel(&delegator_group_id);
    // Event is not yet accepted.
    assert!(kel.is_none());

    // Querying mailbox to get multisig request
    let query =
        delegator_identifier2.query_mailbox(&delegator_identifier2.id(), &[witness_id.clone()])?;

    for qry in query {
        let signature = SelfSigningPrefix::Ed25519Sha512(delegator_km2.sign(&qry.encode()?)?);
        let action_required = delegator_identifier2
            .finalize_query_mailbox(vec![(qry, signature)])
            .await?;

        match &action_required[0] {
            ActionRequired::DelegationRequest(_, _) => {
                unreachable!()
            }
            ActionRequired::MultisigRequest(multisig_event, exn) => {
                let signature_ixn = SelfSigningPrefix::Ed25519Sha512(
                    delegator_km2.sign(&multisig_event.encode()?)?,
                );
                let signature_exn =
                    SelfSigningPrefix::Ed25519Sha512(delegator_km2.sign(&exn.encode()?)?);
                delegator_identifier2
                    .finalize_group_event(
                        &multisig_event.encode()?,
                        signature_ixn.clone(),
                        vec![(exn.encode()?, signature_exn)],
                    )
                    .await?;
            }
        };
    }

    // Query to get events signed by other participants
    let query = delegator_identifier1.query_mailbox(&delegator_group_id, &[witness_id.clone()])?;

    for qry in query {
        let signature = SelfSigningPrefix::Ed25519Sha512(delegator_km1.sign(&qry.encode()?)?);
        delegator_identifier1
            .finalize_query_mailbox(vec![(qry, signature)])
            .await?;
    }

    // Query to have receipt of group inception
    let query = delegator_identifier1.query_mailbox(&delegator_group_id, &[witness_id.clone()])?;

    for qry in query {
        let signature = SelfSigningPrefix::Ed25519Sha512(delegator_km1.sign(&qry.encode()?)?);
        delegator_identifier1
            .finalize_query_mailbox(vec![(qry, signature)])
            .await?;
    }

    let group_state_1 = delegator_identifier1.find_state(&delegator_group_id)?;
    assert_eq!(group_state_1.sn, 0);

    // Query to have receipt of group inception
    let query = delegator_identifier2.query_mailbox(&delegator_group_id, &[witness_id.clone()])?;

    for qry in query {
        let signature = SelfSigningPrefix::Ed25519Sha512(delegator_km2.sign(&qry.encode()?)?);
        delegator_identifier2
            .finalize_query_mailbox(vec![(qry, signature)])
            .await?;
    }

    let group_state_2 = delegator_identifier2.find_state(&delegator_group_id)?;
    assert_eq!(group_state_2.sn, 0);

    println!("Delegator: {}", &delegator_group_id);
    println!(
        "\tparticipants: {:?}",
        &[&delegator_identifier1, &delegator_identifier2]
            .iter()
            .map(|part| part.id().to_string())
            .collect::<Vec<_>>()
    );

    // Setup delegatee identifier. It will be multisig group.
    // Setup identifier for first group participant.
    let delegatee_root_0 = Builder::new().prefix("test-db01").tempdir().unwrap();
    let (mut delegatee_identifier1, delegatee_km1, _delegatee_controller1) = setup_identifier(
        delegatee_root_0.path(),
        vec![witness_oobi.clone()],
        None,
        None,
    )
    .await;

    assert!(delegatee_identifier1.get_own_kel().is_some());

    // Setup identifier for second group participant.
    let delegatee_root_1 = Builder::new().prefix("test-db02").tempdir().unwrap();
    let (mut delegatee_identifier2, delegatee_km2, _delegatee_controller2) = setup_identifier(
        delegatee_root_1.path(),
        vec![witness_oobi.clone()],
        None,
        None,
    )
    .await;

    assert!(delegatee_identifier2.get_own_kel().is_some());

    // Provide second identifier's KEL to first identifier.
    let id2_kel = delegatee_identifier2.get_own_kel().unwrap();
    for msg in id2_kel {
        delegatee_identifier1
            .known_events
            .process(&Message::Notice(msg))
            .unwrap();
    }

    let state = delegatee_identifier1
        .find_state(delegatee_identifier2.id())
        .unwrap();
    assert_eq!(state.sn, 0);

    // Provide first identifier's KEL to second identifier.
    let id1_kel = delegatee_identifier1.get_own_kel().unwrap();
    for msg in id1_kel {
        delegatee_identifier2
            .known_events
            .process(&Message::Notice(msg))
            .unwrap();
    }

    let state = delegatee_identifier2
        .find_state(delegatee_identifier1.id())
        .unwrap();
    assert_eq!(state.sn, 0);

    // Identifier 1 initiate group inception
    let (delegatee_group_inception, exn_messages) = delegatee_identifier1.incept_group(
        vec![delegatee_identifier2.id().clone()],
        2,
        Some(2),
        Some(vec![witness_id.clone()]),
        Some(1),
        Some(delegator_group_id.clone()),
    )?;

    let signature_icp =
        SelfSigningPrefix::Ed25519Sha512(delegatee_km1.sign(delegatee_group_inception.as_bytes())?);
    let exns = exn_messages
        .into_iter()
        .map(|exn| {
            let signature_exn =
                SelfSigningPrefix::Ed25519Sha512(delegatee_km1.sign(exn.as_bytes()).unwrap());
            (exn.as_bytes().to_vec(), signature_exn)
        })
        .collect();

    // Group initiator needs to use `finalize_group_incept` instead of just
    // `finalize_event`, to send multisig request to other group participants.
    // Identifier who get this request from mailbox, can use just `finalize_event`
    let delegatee_group_id = delegatee_identifier1
        .finalize_group_incept(delegatee_group_inception.as_bytes(), signature_icp, exns)
        .await?;

    let kel = delegatee_identifier1.get_kel(&delegatee_group_id);
    // Event is not yet accepted.
    assert!(kel.is_none());

    // Querying mailbox to get multisig request
    let query =
        delegatee_identifier2.query_mailbox(&delegatee_identifier2.id(), &[witness_id.clone()])?;

    for qry in query {
        let signature = SelfSigningPrefix::Ed25519Sha512(delegatee_km2.sign(&qry.encode()?)?);
        let action_required = delegatee_identifier2
            .finalize_query_mailbox(vec![(qry, signature)])
            .await?;

        match &action_required[0] {
            ActionRequired::DelegationRequest(_, _) => {
                unreachable!()
            }
            ActionRequired::MultisigRequest(multisig_event, exn) => {
                let signature_ixn = SelfSigningPrefix::Ed25519Sha512(
                    delegatee_km2.sign(&multisig_event.encode()?)?,
                );
                let signature_exn =
                    SelfSigningPrefix::Ed25519Sha512(delegatee_km2.sign(&exn.encode()?)?);
                delegatee_identifier2
                    .finalize_group_event(
                        &multisig_event.encode()?,
                        signature_ixn.clone(),
                        vec![(exn.encode()?, signature_exn)],
                    )
                    .await?;
            }
        };
    }

    // Query to get events signed by other participants
    let query = delegatee_identifier1.query_mailbox(&delegatee_group_id, &[witness_id.clone()])?;

    for qry in query {
        let signature = SelfSigningPrefix::Ed25519Sha512(delegatee_km1.sign(&qry.encode()?)?);
        delegatee_identifier1
            .finalize_query_mailbox(vec![(qry, signature)])
            .await?;
    }

    // Delegation accept process
    // Each participant of delegator group asks about his mailbox to get delegated event.
    handle_delegation_request(
        &mut delegator_identifier1,
        &delegator_km1,
        &[witness_id.clone()],
        delegator_group_id.clone(),
        &delegatee_group_id,
    )
    .await
    .unwrap();
    handle_delegation_request(
        &mut delegator_identifier2,
        &delegator_km2,
        &[witness_id.clone()],
        delegator_group_id.clone(),
        &delegatee_group_id,
    )
    .await
    .unwrap();

    // ixn was accepted.
    let delegator_state = controller2.find_state(&delegator_group_id).unwrap();
    assert_eq!(delegator_state.sn, 1);

    // Query for receipts and second group participant ixn
    let query = delegator_identifier1.query_mailbox(&delegator_group_id, &[witness_id.clone()])?;

    for qry in query {
        let signature = SelfSigningPrefix::Ed25519Sha512(delegator_km1.sign(&qry.encode()?)?);
        let action_required = delegator_identifier1
            .finalize_query_mailbox(vec![(qry, signature)])
            .await
            .unwrap();
        assert!(action_required.is_empty());
    }

    let delegators_state = controller1.find_state(&delegator_group_id).unwrap();
    assert_eq!(delegators_state.sn, 1);

    // Process delegator's icp by identifier who has requested delegation.
    // TODO how child should get delegator kel?
    let delegators_kel = controller1
        .get_kel_with_receipts(&delegator_group_id)
        .unwrap();
    delegatee_identifier1
        .known_events
        .process(&Message::Notice(delegators_kel[0].clone()))?; // icp

    let state = delegatee_identifier1.find_state(&delegator_group_id)?;
    assert_eq!(state.sn, 0);

    delegatee_identifier2
        .known_events
        .process(&Message::Notice(delegators_kel[0].clone()))?; // icp

    let state = delegatee_identifier2.find_state(&delegator_group_id)?;
    assert_eq!(state.sn, 0);

    // Ask about delegated identifier mailbox. Should get delegating event.
    let query = delegatee_identifier1.query_mailbox(&delegatee_group_id, &[witness_id.clone()])?;

    for qry in query {
        let signature = SelfSigningPrefix::Ed25519Sha512(delegatee_km1.sign(&qry.encode()?)?);
        let ar = delegatee_identifier1
            .finalize_query_mailbox(vec![(qry, signature)])
            .await?;
        assert!(ar.is_empty())
    }

    // Query to get receipts of delegated event
    let query = delegatee_identifier1.query_mailbox(&delegatee_group_id, &[witness_id.clone()])?;

    for qry in query {
        let signature = SelfSigningPrefix::Ed25519Sha512(delegatee_km1.sign(&qry.encode()?)?);
        let ar = delegatee_identifier1
            .finalize_query_mailbox(vec![(qry, signature)])
            .await?;
        assert!(ar.is_empty())
    }

    let state = delegatee_identifier1
        .find_state(&delegatee_group_id)
        .unwrap();
    assert_eq!(state.sn, 0);

    let state = delegatee_identifier1
        .find_state(&delegator_group_id)
        .unwrap();
    assert_eq!(state.sn, 1);

    // Ask about delegated identifier mailbox
    let query = delegatee_identifier2.query_mailbox(&delegatee_group_id, &[witness_id.clone()])?;

    for qry in query {
        let signature = SelfSigningPrefix::Ed25519Sha512(delegatee_km2.sign(&qry.encode()?)?);
        let ar = delegatee_identifier2
            .finalize_query_mailbox(vec![(qry, signature)])
            .await
            .unwrap();
        assert!(ar.is_empty())
    }

    let state = delegatee_identifier2
        .find_state(&delegatee_group_id)
        .unwrap();
    assert_eq!(state.sn, 0);

    let state = delegatee_identifier2
        .find_state(&delegator_group_id)
        .unwrap();
    assert_eq!(state.sn, 1);

    Ok(())
}
