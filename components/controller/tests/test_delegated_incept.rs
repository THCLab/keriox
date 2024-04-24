use std::{collections::HashMap, sync::Arc};

use keri_controller::{
    config::ControllerConfig, controller::Controller, error::ControllerError, identifier::query::QueryResponse, mailbox_updating::ActionRequired, LocationScheme
};
use keri_core::{
    event_message::signed_event_message::Message,
    prefix::{BasicPrefix, IdentifierPrefix, IndexedSignature, SelfSigningPrefix},
    signer::{CryptoBox, KeyManager},
    transport::test::{TestActorMap, TestTransport},
};
use tempfile::Builder;
use url::Host;
use witness::{WitnessEscrowConfig, WitnessListener};

#[async_std::test]
async fn test_delegated_incept() -> Result<(), ControllerError> {
    use url::Url;
    let root = Builder::new().prefix("test-db").tempdir().unwrap();
    let root2 = Builder::new().prefix("test-db2").tempdir().unwrap();

    // Setup test witness
    let witness = {
        let seed = "AK8F6AAiYDpXlWdj2O5F5-6wNCCNJh2A4XOlqwR_HwwH";
        let witness_root = Builder::new().prefix("test-wit1-db").tempdir().unwrap();
        Arc::new(
            WitnessListener::setup(
                url::Url::parse("http://witness1:3232/").unwrap(),
                witness_root.path(),
                Some(seed.to_string()),
                WitnessEscrowConfig::default(),
            )
            .unwrap(),
        )
    };

    let witness_id_basic = witness.get_prefix();
    let witness_id = IdentifierPrefix::Basic(witness_id_basic.clone());
    assert_eq!(
        witness_id.to_string(),
        "BErocgXD2RGSyvn3MObcx59jeOsEQhv2TqHirVkzrp0Q"
    );
    let wit_location = LocationScheme {
        eid: witness_id,
        scheme: keri_core::oobi::Scheme::Http,
        url: Url::parse("http://witness1:3232").unwrap(),
    };

    let mut actors: TestActorMap = HashMap::new();
    actors.insert((Host::Domain("witness1".to_string()), 3232), witness);
    let transport = TestTransport::new(actors);

    // Setup delegatee identifier
    let delegatee_controller = Arc::new(Controller::new(ControllerConfig {
        db_path: root.path().to_owned(),
        transport: Box::new(transport.clone()),
        ..Default::default()
    })?);

    let delegatee_keypair = CryptoBox::new()?;

    let pk = BasicPrefix::Ed25519(delegatee_keypair.public_key());
    let npk = BasicPrefix::Ed25519(delegatee_keypair.next_public_key());

    let icp_event = delegatee_controller
        .incept(vec![pk], vec![npk], vec![wit_location.clone()], 1)
        .await?;
    let signature = SelfSigningPrefix::Ed25519Sha512(delegatee_keypair.sign(icp_event.as_bytes())?);

    let mut delegatee_identifier =
        delegatee_controller.finalize_incept(icp_event.as_bytes(), &signature)?;
    delegatee_identifier.notify_witnesses().await?;

    // Quering mailbox to get receipts
    let query = delegatee_identifier
        .query_mailbox(delegatee_identifier.id(), &[witness_id_basic.clone()])?;

    for qry in query {
        let signature = SelfSigningPrefix::Ed25519Sha512(delegatee_keypair.sign(&qry.encode()?)?);
        delegatee_identifier
            .finalize_query(vec![(qry, signature)])
            .await?;
    }
    println!("Delegatee: {}", &delegatee_identifier.id());

    // Setup delegator identifier
    let delegator_controller = Arc::new(Controller::new(ControllerConfig {
        db_path: root2.path().to_owned(),
        transport: Box::new(transport.clone()),
        ..Default::default()
    })?);
    let delegator_keyipair = CryptoBox::new()?;
    let pk = BasicPrefix::Ed25519(delegator_keyipair.public_key());
    let npk = BasicPrefix::Ed25519(delegator_keyipair.next_public_key());

    let icp_event = delegator_controller
        .incept(vec![pk], vec![npk], vec![wit_location], 1)
        .await?;
    let signature =
        SelfSigningPrefix::Ed25519Sha512(delegator_keyipair.sign(icp_event.as_bytes())?);

    let mut delegator = delegator_controller.finalize_incept(icp_event.as_bytes(), &signature)?;
    delegator.notify_witnesses().await?;

    // Quering mailbox to get receipts
    let query = delegator.query_mailbox(&delegator.id(), &[witness_id_basic.clone()])?;

    for qry in query {
        let signature = SelfSigningPrefix::Ed25519Sha512(delegator_keyipair.sign(&qry.encode()?)?);
        let ar = delegator.finalize_query(vec![(qry, signature)]).await?;
        matches!(ar, QueryResponse::Updates);
    }

    // Generate delegated inception
    let (delegated_inception, exn_messages) = delegatee_identifier.incept_group(
        vec![],
        1,
        Some(vec![witness_id_basic.clone()]),
        Some(1),
        Some(delegator.id().clone()),
    )?;

    let signature_icp =
        SelfSigningPrefix::Ed25519Sha512(delegatee_keypair.sign(delegated_inception.as_bytes())?);
    let signature_exn =
        SelfSigningPrefix::Ed25519Sha512(delegatee_keypair.sign(exn_messages[0].as_bytes())?);

    // Group initiator needs to use `finalize_group_incept` instead of just
    // `finalize_event`, to send multisig request to other group participants or delegator.
    // Identifier who get this request from mailbox, can use just `finalize_event`
    let delegate_id = delegatee_identifier
        .finalize_group_incept(
            delegated_inception.as_bytes(),
            signature_icp.clone(),
            vec![(exn_messages[0].as_bytes().to_vec(), signature_exn.clone())],
        )
        .await?;

    println!("before get_kel_messages_with_receipts");
    let kel = delegatee_controller.get_kel_with_receipts(&delegate_id);
    // Event is not yet accepted. Missing delegating event.
    println!("after get_kel_messages_with_receipts");
    assert!(kel.is_none());

    // Delegator asks about his mailbox to get delegated event.
    let query = delegator.query_mailbox(delegator.id(), &[witness_id_basic.clone()])?;

    for qry in query {
        let signature = SelfSigningPrefix::Ed25519Sha512(delegator_keyipair.sign(&qry.encode()?)?);
        let ar = delegator.finalize_query(vec![(qry, signature)]).await?;
        let ar = match ar {
            QueryResponse::ActionRequired(ar) => ar,
            _ => unreachable!()
        };
        assert_eq!(ar.len(), 1);
        match &ar[0] {
            ActionRequired::MultisigRequest(_, _) => unreachable!(),
            ActionRequired::DelegationRequest(delegating_event, exn) => {
                let signature_ixn = SelfSigningPrefix::Ed25519Sha512(
                    delegator_keyipair.sign(&delegating_event.encode()?)?,
                );
                let signature_exn =
                    SelfSigningPrefix::Ed25519Sha512(delegator_keyipair.sign(&exn.encode()?)?);
                delegator
                    .finalize_group_incept(
                        &delegating_event.encode()?,
                        signature_ixn.clone(),
                        vec![],
                    )
                    .await?;
                delegator.notify_witnesses().await?;

                // Query for receipts
                let query = delegator.query_mailbox(delegator.id(), &[witness_id_basic.clone()])?;

                for qry in query {
                    let signature =
                        SelfSigningPrefix::Ed25519Sha512(delegator_keyipair.sign(&qry.encode()?)?);
                    let action_required = delegator.finalize_query(vec![(qry, signature)]).await?;
                    matches!(action_required, QueryResponse::Updates);
                }
                let data_signature = IndexedSignature::new_both_same(signature_ixn, 0);

                delegator
                    .finalize_exchange(&exn.encode()?, signature_exn, data_signature)
                    .await?;

                // ixn was accepted
                let delegators_state = delegator_controller.find_state(delegator.id())?;
                assert_eq!(delegators_state.sn, 1);
            }
        };
    }

    // Repeat query and expect 0 required actions.
    let query = delegator.query_mailbox(delegator.id(), &[witness_id_basic.clone()])?;
    for qry in query {
        let signature = SelfSigningPrefix::Ed25519Sha512(delegator_keyipair.sign(&qry.encode()?)?);
        let ar = delegator.finalize_query(vec![(qry, signature)]).await?;
        matches!(ar, QueryResponse::Updates);
    }

    // Process delegator's icp by identifier who'll request delegation.
    // TODO how child should get delegators kel?
    let delegators_kel = delegator_controller
        .get_kel_with_receipts(&delegator.id())
        .unwrap();
    delegatee_controller
        .known_events
        .save(&Message::Notice(delegators_kel[0].clone()))?; // icp
    delegatee_controller
        .known_events
        .save(&Message::Notice(delegators_kel[1].clone()))?; // receipt

    // Ask about delegated identifier mailbox
    let query = delegatee_identifier.query_mailbox(&delegate_id, &[witness_id_basic.clone()])?;

    for qry in query {
        let signature = SelfSigningPrefix::Ed25519Sha512(delegatee_keypair.sign(&qry.encode()?)?);
        let ar = delegatee_identifier
            .finalize_query(vec![(qry, signature)])
            .await?;
        matches!(ar, QueryResponse::Updates);
    }

    let state = delegatee_identifier.find_state(delegator.id())?;
    assert_eq!(state.sn, 1);

    // Child kel is not yet accepted
    let state = delegatee_identifier.find_state(&delegate_id);
    // assert_eq!(state, None);
    assert!(state.is_err());

    // Get mailbox for receipts.
    let query = delegatee_identifier.query_mailbox(&delegate_id, &[witness_id_basic.clone()])?;

    for qry in query {
        let signature = SelfSigningPrefix::Ed25519Sha512(delegatee_keypair.sign(&qry.encode()?)?);
        let ar = delegatee_identifier
            .finalize_query(vec![(qry, signature)])
            .await?;
        matches!(ar, QueryResponse::Updates);
    }

    // Child kel is accepted
    let state = delegatee_identifier.find_state(&delegate_id)?;
    assert_eq!(state.sn, 0);

    Ok(())
}
