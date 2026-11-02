use keri_controller::{
    error::ControllerError, ActionRequired, KeyManager, SelfSigningPrefix,
};
use keri_core::actor::prelude::Message;
use keri_tests::{
    collect_receipts, handle_delegation_request, settings::InfrastructureContext, setup_identifier,
};
use tempfile::Builder;
use test_context::test_context;

#[test_context(InfrastructureContext)]
#[actix_rt::test]
async fn multi_delegator_multi_delegatee(
    ctx: &mut InfrastructureContext,
) -> Result<(), ControllerError> {
    let (witness_id, witness_oobi) = ctx.first_witness_data();

    // Setup delegator identifier. It will be multisig group.
    // Setup identifier for first group participant.
    let root_0 = Builder::new().prefix("test-db1").tempdir().unwrap();
    let (mut delegator_identifier1, delegator_km1, controller1) =
        setup_identifier(root_0.path(), vec![witness_oobi.clone()], None).await;

    assert!(delegator_identifier1.get_own_kel().is_some());

    // Setup identifier for second group participant.
    let root_1 = Builder::new().prefix("test-db2").tempdir().unwrap();
    let (mut delegator_identifier2, delegator_km2, controller2) =
        setup_identifier(root_1.path(), vec![witness_oobi.clone()], None).await;

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
    let exn_index_signature = delegator_identifier1.sign_with_index(signature_exn, 0)?;

    // Group initiator needs to use `finalize_group_incept` instead of just
    // `finalize_event`: it returns the forwards that carry the multisig
    // request to other group participants.
    let (delegator_group_id, forwards) = delegator_identifier1
        .finalize_group_incept(
            group_inception.as_bytes(),
            signature_icp,
            vec![(exn_messages[0].as_bytes().to_vec(), exn_index_signature)],
        )
        .await?;

    let kel = delegator_identifier1.get_kel(&delegator_group_id);
    // Event is not yet accepted.
    assert!(kel.is_none());

    // Deliver the multisig request to the second participant
    let [request] = forwards.as_slice() else {
        panic!("one forward, to the other participant: {forwards:?}")
    };
    assert_eq!(&request.to, delegator_identifier2.id());
    let action_required = delegator_identifier2
        .receive_forwards(&request.message)
        .await?;

    let signed_by_2 = match &action_required[0] {
        ActionRequired::DelegationRequest(_, _) => {
            unreachable!()
        }
        ActionRequired::MultisigRequest(multisig_event, exn) => {
            let signature_ixn =
                SelfSigningPrefix::Ed25519Sha512(delegator_km2.sign(&multisig_event.encode()?)?);
            let signature_exn =
                SelfSigningPrefix::Ed25519Sha512(delegator_km2.sign(&exn.encode()?)?);
            let exn_index_signature = delegator_identifier2.sign_with_index(signature_exn, 0)?;
            delegator_identifier2
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
    let action_required = delegator_identifier1
        .receive_forwards(&signed.message)
        .await?;
    assert!(action_required.is_empty());

    // Query to have receipt of group inception
    collect_receipts(
        &mut delegator_identifier1,
        &delegator_km1,
        &delegator_group_id,
        &[witness_id.clone()],
    )
    .await?;

    let group_state_1 = delegator_identifier1.find_state(&delegator_group_id)?;
    assert_eq!(group_state_1.sn, 0);

    // Query to have receipt of group inception
    collect_receipts(
        &mut delegator_identifier2,
        &delegator_km2,
        &delegator_group_id,
        &[witness_id.clone()],
    )
    .await?;

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
    )
    .await;

    assert!(delegatee_identifier1.get_own_kel().is_some());

    // Setup identifier for second group participant.
    let delegatee_root_1 = Builder::new().prefix("test-db02").tempdir().unwrap();
    let (mut delegatee_identifier2, delegatee_km2, _delegatee_controller2) = setup_identifier(
        delegatee_root_1.path(),
        vec![witness_oobi.clone()],
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

            let exn_index_signature = delegatee_identifier1
                .sign_with_index(signature_exn, 0)
                .unwrap();
            (exn.as_bytes().to_vec(), exn_index_signature)
        })
        .collect();

    // Group initiator needs to use `finalize_group_incept` instead of just
    // `finalize_event`: it returns the forwards that carry the multisig
    // request to other group participants and the delegation request to
    // the delegator.
    let (delegatee_group_id, forwards) = delegatee_identifier1
        .finalize_group_incept(delegatee_group_inception.as_bytes(), signature_icp, exns)
        .await?;

    let kel = delegatee_identifier1.get_kel(&delegatee_group_id);
    // Event is not yet accepted.
    assert!(kel.is_none());

    let [multisig_request, delegation_request] = forwards.as_slice() else {
        panic!("two forwards, to the other participant and the delegator: {forwards:?}")
    };
    assert_eq!(&multisig_request.to, delegatee_identifier2.id());
    assert_eq!(delegation_request.to, delegator_group_id);

    // Deliver the multisig request to the second participant
    let action_required = delegatee_identifier2
        .receive_forwards(&multisig_request.message)
        .await?;

    let signed_by_2 = match &action_required[0] {
        ActionRequired::DelegationRequest(_, _) => {
            unreachable!()
        }
        ActionRequired::MultisigRequest(multisig_event, exn) => {
            let signature_ixn =
                SelfSigningPrefix::Ed25519Sha512(delegatee_km2.sign(&multisig_event.encode()?)?);
            let signature_exn =
                SelfSigningPrefix::Ed25519Sha512(delegatee_km2.sign(&exn.encode()?)?);
            let exn_index_signature = delegatee_identifier2
                .sign_with_index(signature_exn, 0)
                .unwrap();
            delegatee_identifier2
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
    assert_eq!(signed.to, delegatee_group_id);
    let _action_required = delegatee_identifier1
        .receive_forwards(&signed.message)
        .await?;

    // Delegation accept process
    // The delegation request is a forward to the delegator group, delivered
    // to each of its participants, which verify it against the requester's
    // KEL.
    let requester_kel = delegatee_identifier1.get_own_kel().unwrap();
    for participant in [&delegator_identifier1, &delegator_identifier2] {
        for notice in &requester_kel {
            participant
                .known_events
                .process(&Message::Notice(notice.clone()))?;
        }
    }

    let from_1 = handle_delegation_request(
        &mut delegator_identifier1,
        &delegator_km1,
        &[witness_id.clone()],
        delegator_group_id.clone(),
        &delegatee_group_id,
        &delegation_request.message,
    )
    .await
    .unwrap();

    let from_2 = handle_delegation_request(
        &mut delegator_identifier2,
        &delegator_km2,
        &[witness_id.clone()],
        delegator_group_id.clone(),
        &delegatee_group_id,
        &delegation_request.message,
    )
    .await
    .unwrap();

    // ixn was accepted.
    let delegator_state = controller2.find_state(&delegator_group_id).unwrap();
    assert_eq!(delegator_state.sn, 1);

    // Each participant forwards the signed ixn to the group, and the
    // approval to the delegatee group.
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
    assert!(approvals
        .iter()
        .all(|approval| approval.to == delegatee_group_id));

    // Deliver the second group participant ixn and query for receipts
    let _action_required = delegator_identifier1
        .receive_forwards(&to_group_2[0].message)
        .await
        .unwrap();
    collect_receipts(
        &mut delegator_identifier1,
        &delegator_km1,
        &delegator_group_id,
        &[witness_id.clone()],
    )
    .await
    .unwrap();
    let _action_required = delegator_identifier2
        .receive_forwards(&to_group_1[0].message)
        .await
        .unwrap();

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

    // The approvals are verified against the delegator group participants'
    // KELs.
    for participant in [&delegator_identifier1, &delegator_identifier2] {
        for notice in participant.get_own_kel().unwrap() {
            delegatee_identifier1
                .known_events
                .process(&Message::Notice(notice.clone()))?;
            delegatee_identifier2
                .known_events
                .process(&Message::Notice(notice))?;
        }
    }
    let approvals = approvals
        .iter()
        .flat_map(|approval| approval.message.clone())
        .collect::<Vec<_>>();

    // Deliver the approvals to the delegatee group participants. Should
    // bring the delegating event.
    let ar = delegatee_identifier1.receive_forwards(&approvals).await?;
    assert!(ar.is_empty());

    // Query to get receipts of delegated event
    collect_receipts(
        &mut delegatee_identifier1,
        &delegatee_km1,
        &delegatee_group_id,
        &[witness_id.clone()],
    )
    .await?;

    let state = delegatee_identifier1
        .find_state(&delegatee_group_id)
        .unwrap();
    assert_eq!(state.sn, 0);

    let state = delegatee_identifier1
        .find_state(&delegator_group_id)
        .unwrap();
    assert_eq!(state.sn, 1);

    // Deliver the approvals to the second participant and query for receipts
    let _ar = delegatee_identifier2
        .receive_forwards(&approvals)
        .await
        .unwrap();
    collect_receipts(
        &mut delegatee_identifier2,
        &delegatee_km2,
        &delegatee_group_id,
        &[witness_id.clone()],
    )
    .await
    .unwrap();

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
