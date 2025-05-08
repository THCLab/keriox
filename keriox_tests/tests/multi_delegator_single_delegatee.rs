use keri_controller::{
    error::ControllerError, mailbox_updating::ActionRequired, KeyManager, SelfSigningPrefix,
};
use keri_core::actor::prelude::Message;
use keri_tests::{handle_delegation_request, settings::InfrastructureContext, setup_identifier};
use tempfile::Builder;
use test_context::test_context;

#[test_context(InfrastructureContext)]
#[actix_rt::test]
async fn multi_delegator_single_delegatee(
    ctx: &mut InfrastructureContext,
) -> Result<(), ControllerError> {
    let (witness_id, witness_oobi) = ctx.first_witness_data();

    // Setup delegator identifier. It will be multisig group.
    // Setup identifier for first group participant.
    let root_0 = Builder::new().prefix("test-db1").tempdir().unwrap();
    let (mut identifier1, km1, controller1) =
        setup_identifier(root_0.path(), vec![witness_oobi.clone()], None, None).await;

    assert!(identifier1.get_own_kel().is_some());

    // Setup identifier for second group participant.
    let root_1 = Builder::new().prefix("test-db2").tempdir().unwrap();
    let (mut identifier2, km2, controller2) =
        setup_identifier(root_1.path(), vec![witness_oobi.clone()], None, None).await;

    assert!(identifier2.get_own_kel().is_some());

    // Provide second identifier's KEL to first identifier. Is necessary to create multisig event.
    let id2_kel = identifier2.get_own_kel().unwrap();
    for msg in id2_kel {
        identifier1
            .known_events
            .process(&Message::Notice(msg))
            .unwrap();
    }

    let state = identifier1.find_state(identifier2.id()).unwrap();
    assert_eq!(state.sn, 0);

    // Provide first identifier's KEL to second identifier.
    let id1_kel = identifier1.get_own_kel().unwrap();
    for msg in id1_kel {
        identifier2
            .known_events
            .process(&Message::Notice(msg))
            .unwrap();
    }

    let state = identifier2.find_state(identifier1.id()).unwrap();
    assert_eq!(state.sn, 0);

    // Identifier 1 initiate group inception
    let (group_inception, exn_messages) = identifier1.incept_group(
        vec![identifier2.id().clone()],
        2,
        Some(2),
        Some(vec![witness_id.clone()]),
        Some(1),
        None,
    )?;

    let signature_icp = SelfSigningPrefix::Ed25519Sha512(km1.sign(group_inception.as_bytes())?);
    let signature_exn = SelfSigningPrefix::Ed25519Sha512(km1.sign(exn_messages[0].as_bytes())?);
    let exn_index_signature = identifier1.sign_with_index(signature_exn, 0)?;

    // Group initiator needs to use `finalize_group_incept` instead of just
    // `finalize_event`, to send multisig request to other group participants.
    // Identifier who get this request from mailbox, can use just `finalize_event`
    let delegator_group_id = identifier1
        .finalize_group_incept(
            group_inception.as_bytes(),
            signature_icp,
            vec![(exn_messages[0].as_bytes().to_vec(), exn_index_signature)],
        )
        .await?;

    let kel = identifier1.get_kel(&delegator_group_id);
    // Event is not yet accepted.
    assert!(kel.is_none());

    // Querying mailbox to get multisig request
    let query = identifier2.query_mailbox(&identifier2.id(), &[witness_id.clone()])?;

    for qry in query {
        let signature = SelfSigningPrefix::Ed25519Sha512(km2.sign(&qry.encode()?)?);
        let action_required = identifier2
            .finalize_query_mailbox(vec![(qry, signature)])
            .await?;

        match &action_required[0] {
            ActionRequired::DelegationRequest(_, _) => {
                unreachable!()
            }
            ActionRequired::MultisigRequest(multisig_event, exn) => {
                let signature_ixn =
                    SelfSigningPrefix::Ed25519Sha512(km2.sign(&multisig_event.encode()?)?);
                let signature_exn = SelfSigningPrefix::Ed25519Sha512(km2.sign(&exn.encode()?)?);
                let exn_index_signature = identifier2.sign_with_index(signature_exn, 0)?;
                identifier2
                    .finalize_group_event(
                        &multisig_event.encode()?,
                        signature_ixn.clone(),
                        vec![(exn.encode()?, exn_index_signature)],
                    )
                    .await?;
            }
        };
    }

    // Query to get events signed by other participants
    let query = identifier1.query_mailbox(&delegator_group_id, &[witness_id.clone()])?;

    for qry in query {
        let signature = SelfSigningPrefix::Ed25519Sha512(km1.sign(&qry.encode()?)?);
        identifier1
            .finalize_query_mailbox(vec![(qry, signature)])
            .await?;
    }

    // Query to have receipt of group inception
    let query = identifier1.query_mailbox(&delegator_group_id, &[witness_id.clone()])?;

    for qry in query {
        let signature = SelfSigningPrefix::Ed25519Sha512(km1.sign(&qry.encode()?)?);
        identifier1
            .finalize_query_mailbox(vec![(qry, signature)])
            .await?;
    }

    let group_state_1 = identifier1.find_state(&delegator_group_id)?;
    assert_eq!(group_state_1.sn, 0);

    // Query to have receipt of group inception
    let query = identifier2.query_mailbox(&delegator_group_id, &[witness_id.clone()])?;

    for qry in query {
        let signature = SelfSigningPrefix::Ed25519Sha512(km2.sign(&qry.encode()?)?);
        identifier2
            .finalize_query_mailbox(vec![(qry, signature)])
            .await?;
    }

    let group_state_2 = identifier2.find_state(&delegator_group_id)?;
    assert_eq!(group_state_2.sn, 0);

    println!("Delegator: {}", &delegator_group_id);
    println!(
        "\tparticipants: {:?}",
        &[&identifier1, &identifier2]
            .iter()
            .map(|part| part.id().to_string())
            .collect::<Vec<_>>()
    );

    // Setup temporary directories for delegatee identifier
    let delegatee_root = Builder::new().prefix("test-db2").tempdir().unwrap(); // Setup delegatee

    let (mut temporary_delegatee_identifier, delegatee_keypair, _) =
        setup_identifier(delegatee_root.path(), vec![witness_oobi], None, None).await;

    // Generate delegated inception and exn, that is provide delegation request to delegator.
    let (delegated_inception, exn_messages) = temporary_delegatee_identifier.incept_group(
        vec![],
        1,
        Some(1),
        Some(vec![witness_id.clone()]),
        Some(1),
        Some(delegator_group_id.clone()),
    )?;

    let signature_icp =
        SelfSigningPrefix::Ed25519Sha512(delegatee_keypair.sign(delegated_inception.as_bytes())?);
    let signature_exn =
        SelfSigningPrefix::Ed25519Sha512(delegatee_keypair.sign(exn_messages[0].as_bytes())?);
    let exn_index_signature = temporary_delegatee_identifier.sign_with_index(signature_exn, 0)?;

    let delegatee_id = temporary_delegatee_identifier
        .finalize_group_incept(
            delegated_inception.as_bytes(),
            signature_icp.clone(),
            vec![(exn_messages[0].as_bytes().to_vec(), exn_index_signature)],
        )
        .await?;

    let kel = temporary_delegatee_identifier.get_kel(&delegatee_id);
    // Event is not yet accepted. Missing delegating event.
    assert!(kel.is_none());

    // Delegation accept process
    // Each participant of delegator group asks about his mailbox to get delegated event.
    handle_delegation_request(
        &mut identifier1,
        &km1,
        &[witness_id.clone()],
        delegator_group_id.clone(),
        &delegatee_id,
    )
    .await
    .unwrap();

    handle_delegation_request(
        &mut identifier2,
        &km2,
        &[witness_id.clone()],
        delegator_group_id.clone(),
        &delegatee_id,
    )
    .await
    .unwrap();

    // ixn was accepted
    let delegator_state = controller2.find_state(&delegator_group_id)?;
    assert_eq!(delegator_state.sn, 1);

    // Query for receipts and second group participant ixn
    let query = identifier1.query_mailbox(&delegator_group_id, &[witness_id.clone()])?;
    let queries_and_signatures = query.into_iter().map(|qry| {
        let sig = SelfSigningPrefix::Ed25519Sha512(km1.sign(&qry.encode().unwrap()).unwrap());
        (qry, sig)
    });
    let _action_required = identifier1
        .finalize_query_mailbox(queries_and_signatures.collect())
        .await
        .unwrap();

    let delegators_state = controller1.find_state(&delegator_group_id)?;
    assert_eq!(delegators_state.sn, 1);

    // Process delegator's icp by identifier who'll request delegation.
    // TODO how child should get delegators kel?
    let delegators_kel = controller1
        .get_kel_with_receipts(&delegator_group_id)
        .unwrap();
    temporary_delegatee_identifier
        .known_events
        .process(&Message::Notice(delegators_kel[0].clone()))?; // icp

    let state = temporary_delegatee_identifier.find_state(&delegator_group_id)?;
    assert_eq!(state.sn, 0);
    // Ask about delegated identifier mailbox
    let query =
        temporary_delegatee_identifier.query_mailbox(&delegatee_id, &[witness_id.clone()])?;
    let queries_and_signatures = query
        .into_iter()
        .map(|qry| {
            let sig = SelfSigningPrefix::Ed25519Sha512(
                delegatee_keypair.sign(&qry.encode().unwrap()).unwrap(),
            );
            (qry, sig)
        })
        .collect::<Vec<_>>();

    let _ar = temporary_delegatee_identifier
        .finalize_query_mailbox(queries_and_signatures)
        .await?;

    let state = temporary_delegatee_identifier.find_state(&delegator_group_id)?;
    assert_eq!(state.sn, 1);

    // Child kel is not yet accepted
    let state = temporary_delegatee_identifier.find_state(&delegatee_id);
    assert!(state.is_err());

    // Get mailbox for receipts.
    let query =
        temporary_delegatee_identifier.query_mailbox(&delegatee_id, &[witness_id.clone()])?;

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
