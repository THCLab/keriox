use std::sync::Arc;

use keri_controller::{
    config::ControllerConfig, controller::Controller, error::ControllerError, ActionRequired,
    BasicPrefix, CryptoBox, KeyManager, SelfSigningPrefix,
};
use keri_core::{actor::prelude::Message, prefix::IndexedSignature};
use keri_tests::{collect_receipts, settings::InfrastructureContext};
use tempfile::Builder;
use test_context::test_context;

#[test_context(InfrastructureContext)]
#[actix_rt::test]
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

    // Asking the witness for the KEL to get receipts
    let delegator_id = delegator_identifier.id().clone();
    collect_receipts(
        &mut delegator_identifier,
        &delegator_keypair,
        &delegator_id,
        &[first_witness_id.clone()],
    )
    .await?;
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

    // Asking the witness for the KEL to get receipts
    let temporary_delegatee_id = temporary_delegatee_identifier.id().clone();
    collect_receipts(
        &mut temporary_delegatee_identifier,
        &delegatee_keypair,
        &temporary_delegatee_id,
        &[first_witness_id.clone()],
    )
    .await?;

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
    let exn_index_signature = temporary_delegatee_identifier.sign_with_index(signature_exn, 0)?;

    let (delegatee_id, forwards) = temporary_delegatee_identifier
        .finalize_group_incept(
            delegated_inception.as_bytes(),
            signature_icp.clone(),
            vec![(
                exn_messages[0].as_bytes().to_vec(),
                exn_index_signature.clone(),
            )],
        )
        .await?;

    let kel = delegatee_controller.get_kel_with_receipts(&delegatee_id);
    // Event is not yet accepted. Missing delegating event.
    assert!(kel.is_none());

    // Delegation accept process
    // The delegation request is a forward to the delegator, which verifies
    // it against the requester's KEL.
    let [request] = forwards.as_slice() else {
        panic!("one forward, to the delegator: {forwards:?}")
    };
    assert_eq!(&request.to, delegator_identifier.id());
    for notice in delegatee_controller
        .get_kel_with_receipts(&temporary_delegatee_id)
        .unwrap()
    {
        delegator_controller
            .known_events
            .save(&Message::Notice(notice))?;
    }

    // Delegator receives the request and approves it.
    let ar = delegator_identifier
        .receive_forwards(&request.message)
        .await?;

    assert_eq!(ar.len(), 1);
    let approval = match &ar[0] {
        ActionRequired::MultisigRequest(_, _) => unreachable!(),
        ActionRequired::DelegationRequest(delegating_event, exn) => {
            let signature_ixn = SelfSigningPrefix::Ed25519Sha512(
                delegator_keypair.sign(&delegating_event.encode()?)?,
            );
            let signature_exn =
                SelfSigningPrefix::Ed25519Sha512(delegator_keypair.sign(&exn.encode()?)?);
            delegator_identifier
                .finalize_group_event(&delegating_event.encode()?, signature_ixn.clone(), vec![])
                .await?;
            delegator_identifier.notify_witnesses().await?;

            // Query for receipts
            collect_receipts(
                &mut delegator_identifier,
                &delegator_keypair,
                &delegator_id,
                &[first_witness_id.clone()],
            )
            .await?;
            let data_signature = IndexedSignature::new_both_same(signature_ixn, 0);
            let exn_index_signature = delegator_identifier.sign_with_index(signature_exn, 0)?;

            let approval = delegator_identifier.finalize_exchange(
                &exn.encode()?,
                exn_index_signature,
                &delegating_event,
                data_signature,
            )?;

            // ixn was accepted
            let delegators_state = delegator_controller.find_state(delegator_identifier.id())?;
            assert_eq!(delegators_state.sn, 1);
            approval
        }
    };
    assert_eq!(approval.to, delegatee_id);

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

    // Delegatee receives the approval: the delegating event.
    let ar = temporary_delegatee_identifier
        .receive_forwards(&approval.message)
        .await?;
    assert!(ar.is_empty());

    let state = temporary_delegatee_identifier.find_state(delegator_identifier.id())?;
    assert_eq!(state.sn, 1);

    // Child kel is not yet accepted
    let state = temporary_delegatee_identifier.find_state(&delegatee_id);
    // assert_eq!(state, None);
    assert!(state.is_err());

    // Ask the witness for the delegated KEL to get receipts.
    collect_receipts(
        &mut temporary_delegatee_identifier,
        &delegatee_keypair,
        &delegatee_id,
        &[first_witness_id.clone()],
    )
    .await?;

    // Child kel is accepted
    let state = temporary_delegatee_identifier.find_state(&delegatee_id)?;
    assert_eq!(state.sn, 0);

    Ok(())
}
