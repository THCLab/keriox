use keri_controller::{
    error::ControllerError, mailbox_updating::ActionRequired, KeyManager, SelfSigningPrefix,
};
use keri_core::actor::prelude::Message;
use keri_tests::{
    collect_receipts, handle_delegation_request, settings::InfrastructureContext, setup_identifier,
};
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
        setup_identifier(root_0.path(), vec![witness_oobi.clone()], None).await;

    assert!(identifier1.get_own_kel().is_some());

    // Setup identifier for second group participant.
    let root_1 = Builder::new().prefix("test-db2").tempdir().unwrap();
    let (mut identifier2, km2, controller2) =
        setup_identifier(root_1.path(), vec![witness_oobi.clone()], None).await;

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
    // `finalize_event`: it returns the forwards that carry the multisig
    // request to other group participants.
    let (delegator_group_id, forwards) = identifier1
        .finalize_group_incept(
            group_inception.as_bytes(),
            signature_icp,
            vec![(exn_messages[0].as_bytes().to_vec(), exn_index_signature)],
        )
        .await?;

    let kel = identifier1.get_kel(&delegator_group_id);
    // Event is not yet accepted.
    assert!(kel.is_none());

    // Deliver the multisig request to the second participant
    let [request] = forwards.as_slice() else {
        panic!("one forward, to the other participant: {forwards:?}")
    };
    assert_eq!(&request.to, identifier2.id());
    let action_required = identifier2.receive_forwards(&request.message).await?;

    let signed_by_2 = match &action_required[0] {
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
                .await?
        }
    };

    // Deliver the event signed by the other participant to the first one
    let [signed] = signed_by_2.as_slice() else {
        panic!("one forward, to the group: {signed_by_2:?}")
    };
    assert_eq!(signed.to, delegator_group_id);
    let action_required = identifier1.receive_forwards(&signed.message).await?;
    assert!(action_required.is_empty());

    // Query to have receipt of group inception
    collect_receipts(
        &mut identifier1,
        &km1,
        &delegator_group_id,
        &[witness_id.clone()],
    )
    .await?;

    let group_state_1 = identifier1.find_state(&delegator_group_id)?;
    assert_eq!(group_state_1.sn, 0);

    // Query to have receipt of group inception
    collect_receipts(
        &mut identifier2,
        &km2,
        &delegator_group_id,
        &[witness_id.clone()],
    )
    .await?;

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
        setup_identifier(delegatee_root.path(), vec![witness_oobi], None).await;

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

    let (delegatee_id, forwards) = temporary_delegatee_identifier
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
    // The delegation request is a forward to the delegator group, delivered
    // to each of its participants, which verify it against the requester's
    // KEL.
    let [request] = forwards.as_slice() else {
        panic!("one forward, to the delegator: {forwards:?}")
    };
    assert_eq!(request.to, delegator_group_id);
    let requester_kel = temporary_delegatee_identifier.get_own_kel().unwrap();
    for participant in [&identifier1, &identifier2] {
        for notice in &requester_kel {
            participant
                .known_events
                .process(&Message::Notice(notice.clone()))?;
        }
    }

    let from_1 = handle_delegation_request(
        &mut identifier1,
        &km1,
        &[witness_id.clone()],
        delegator_group_id.clone(),
        &delegatee_id,
        &request.message,
    )
    .await
    .unwrap();

    let from_2 = handle_delegation_request(
        &mut identifier2,
        &km2,
        &[witness_id.clone()],
        delegator_group_id.clone(),
        &delegatee_id,
        &request.message,
    )
    .await
    .unwrap();

    // ixn was accepted
    let delegator_state = controller2.find_state(&delegator_group_id)?;
    assert_eq!(delegator_state.sn, 1);

    // Each participant forwards the signed ixn to the group, and the
    // approval to the delegatee.
    let (to_group_1, approvals_1): (Vec<_>, Vec<_>) = from_1
        .into_iter()
        .partition(|forward| forward.to == delegator_group_id);
    let (to_group_2, approvals_2): (Vec<_>, Vec<_>) = from_2
        .into_iter()
        .partition(|forward| forward.to == delegator_group_id);
    assert_eq!(to_group_1.len(), 1);
    assert_eq!(to_group_2.len(), 1);
    let approvals = approvals_1
        .into_iter()
        .chain(approvals_2)
        .collect::<Vec<_>>();
    assert_eq!(approvals.len(), 2);
    assert!(approvals.iter().all(|approval| approval.to == delegatee_id));

    // Deliver the second group participant ixn and query for receipts
    let _action_required = identifier1
        .receive_forwards(&to_group_2[0].message)
        .await
        .unwrap();
    collect_receipts(
        &mut identifier1,
        &km1,
        &delegator_group_id,
        &[witness_id.clone()],
    )
    .await
    .unwrap();
    let _action_required = identifier2
        .receive_forwards(&to_group_1[0].message)
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

    // The approvals are verified against the group participants' KELs.
    for participant in [&identifier1, &identifier2] {
        for notice in participant.get_own_kel().unwrap() {
            temporary_delegatee_identifier
                .known_events
                .process(&Message::Notice(notice))?;
        }
    }

    // Deliver the approvals to the delegatee
    let stream = approvals
        .iter()
        .flat_map(|approval| approval.message.clone())
        .collect::<Vec<_>>();
    let ar = temporary_delegatee_identifier
        .receive_forwards(&stream)
        .await?;
    assert!(ar.is_empty());

    let state = temporary_delegatee_identifier.find_state(&delegator_group_id)?;
    assert_eq!(state.sn, 1);

    // Child kel is not yet accepted
    let state = temporary_delegatee_identifier.find_state(&delegatee_id);
    assert!(state.is_err());

    // Ask the witness for the delegated KEL to get receipts.
    collect_receipts(
        &mut temporary_delegatee_identifier,
        &delegatee_keypair,
        &delegatee_id,
        &[witness_id.clone()],
    )
    .await?;

    // Child kel is accepted
    let state = temporary_delegatee_identifier.find_state(&delegatee_id)?;
    assert_eq!(state.sn, 0);

    Ok(())
}
