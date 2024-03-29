use std::{collections::HashMap, sync::Arc};

use keri_controller::{
    config::ControllerConfig, error::ControllerError, identifier_controller::IdentifierController,
    mailbox_updating::ActionRequired, BasicPrefix, Controller, CryptoBox, IdentifierPrefix,
    KeyManager, LocationScheme, SelfSigningPrefix,
};
use keri_core::{
    actor::{error::ActorError, SignedQueryError},
    event_message::signed_event_message::Message,
    prefix::IndexedSignature,
    transport::{
        test::{TestActorMap, TestTransport},
        TransportError,
    },
};
use tempfile::Builder;
use url::Host;
use witness::{WitnessEscrowConfig, WitnessListener};

#[async_std::test]
async fn test_delegated_incept() -> Result<(), ControllerError> {
    use url::Url;
    let root = Builder::new().prefix("test-db").tempdir().unwrap();
    let root2 = Builder::new().prefix("test-db2").tempdir().unwrap();

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

    let controller = Arc::new(Controller::new(ControllerConfig {
        db_path: root.path().to_owned(),
        transport: Box::new(transport.clone()),
        ..Default::default()
    })?);
    let controller2 = Arc::new(Controller::new(ControllerConfig {
        db_path: root2.path().to_owned(),
        transport: Box::new(transport.clone()),
        ..Default::default()
    })?);
    let km1 = CryptoBox::new()?;
    let km2 = CryptoBox::new()?;

    let mut identifier1 = {
        let pk = BasicPrefix::Ed25519(km1.public_key());
        let npk = BasicPrefix::Ed25519(km1.next_public_key());

        let icp_event = controller
            .incept(vec![pk], vec![npk], vec![wit_location.clone()], 1)
            .await?;
        let signature = SelfSigningPrefix::Ed25519Sha512(km1.sign(icp_event.as_bytes())?);

        let incepted_identifier = controller
            .finalize_inception(icp_event.as_bytes(), &signature)
            .await?;
        IdentifierController::new(incepted_identifier, controller.clone(), None)
    };
    identifier1.notify_witnesses().await?;

    // Quering mailbox to get receipts
    let query = identifier1.query_mailbox(&identifier1.id, &[witness_id_basic.clone()])?;

    // Query with wrong signature
    {
        let qry = query[0].clone();
        let sig = SelfSigningPrefix::Ed25519Sha512(km2.sign(&qry.encode()?)?);
        let resp = identifier1.finalize_query(vec![(qry, sig)]).await;
        assert!(matches!(
            resp,
            Err(ControllerError::TransportError(
                TransportError::RemoteError(ActorError::QueryError(
                    SignedQueryError::InvalidSignature
                ))
            ))
        ));
    }

    for qry in query {
        let signature = SelfSigningPrefix::Ed25519Sha512(km1.sign(&qry.encode()?)?);
        identifier1.finalize_query(vec![(qry, signature)]).await?;
    }

    let mut delegator = {
        let pk = BasicPrefix::Ed25519(km2.public_key());
        let npk = BasicPrefix::Ed25519(km2.next_public_key());

        let icp_event = controller2
            .incept(vec![pk], vec![npk], vec![wit_location], 1)
            .await?;
        let signature = SelfSigningPrefix::Ed25519Sha512(km2.sign(icp_event.as_bytes())?);

        let incepted_identifier = controller2
            .finalize_inception(icp_event.as_bytes(), &signature)
            .await?;
        IdentifierController::new(incepted_identifier, controller2.clone(), None)
    };
    delegator.notify_witnesses().await?;

    // Quering mailbox to get receipts
    let query = delegator.query_mailbox(&delegator.id, &[witness_id_basic.clone()])?;

    for qry in query {
        let signature = SelfSigningPrefix::Ed25519Sha512(km2.sign(&qry.encode()?)?);
        let ar = delegator.finalize_query(vec![(qry, signature)]).await?;
        assert!(ar.is_empty());
    }

    // Generate delegated inception
    let (delegated_inception, exn_messages) = identifier1.incept_group(
        vec![],
        1,
        Some(vec![witness_id_basic.clone()]),
        Some(1),
        Some(delegator.id.clone()),
    )?;

    let signature_icp = SelfSigningPrefix::Ed25519Sha512(km1.sign(delegated_inception.as_bytes())?);
    let signature_exn = SelfSigningPrefix::Ed25519Sha512(km1.sign(exn_messages[0].as_bytes())?);

    // Send with wrong signature
    let resp = identifier1
        .finalize_group_incept(
            delegated_inception.as_bytes(),
            signature_exn.clone(),
            vec![(exn_messages[0].as_bytes().to_vec(), signature_icp.clone())],
        )
        .await;
    assert!(matches!(
        resp,
        Err(ControllerError::TransportError(
            TransportError::RemoteError(ActorError::KeriError(
                keri_core::error::Error::SignatureVerificationError
            ))
        ))
    ));

    // Group initiator needs to use `finalize_group_incept` instead of just
    // `finalize_event`, to send multisig request to other group participants or delegator.
    // Identifier who get this request from mailbox, can use just `finalize_event`
    let delegate_id = identifier1
        .finalize_group_incept(
            delegated_inception.as_bytes(),
            signature_icp.clone(),
            vec![(exn_messages[0].as_bytes().to_vec(), signature_exn.clone())],
        )
        .await?;

    // Quering mailbox to get receipts
    let query = delegator.query_mailbox(&delegator.id, &[witness_id_basic.clone()])?;

    // Query with wrong signature
    {
        let qry = query[0].clone();
        let sig = SelfSigningPrefix::Ed25519Sha512(km2.sign(b"not actual message")?);
        let resp = identifier1.finalize_query(vec![(qry, sig)]).await;
        assert!(matches!(
            resp,
            Err(ControllerError::TransportError(
                TransportError::RemoteError(ActorError::QueryError(
                    SignedQueryError::InvalidSignature
                ))
            ))
        ));
    }

    println!("before get_kel_messages_with_receipts");
    let kel = controller
        .storage
        .get_kel_messages_with_receipts(&delegate_id, None)?;
    // Event is not yet accepted. Missing delegating event.
    println!("after get_kel_messages_with_receipts");
    assert!(kel.is_none());

    // Delegator asks about his mailbox to get delegated event.
    let query = delegator.query_mailbox(&delegator.id, &[witness_id_basic.clone()])?;

    for qry in query {
        let signature = SelfSigningPrefix::Ed25519Sha512(km2.sign(&qry.encode()?)?);
        let ar = delegator.finalize_query(vec![(qry, signature)]).await?;
        assert_eq!(ar.len(), 1);
        match &ar[0] {
            ActionRequired::MultisigRequest(_, _) => unreachable!(),
            ActionRequired::DelegationRequest(delegating_event, exn) => {
                let signature_ixn =
                    SelfSigningPrefix::Ed25519Sha512(km2.sign(&delegating_event.encode()?)?);
                let signature_exn = SelfSigningPrefix::Ed25519Sha512(km2.sign(&exn.encode()?)?);
                delegator
                    .finalize_group_incept(
                        &delegating_event.encode()?,
                        signature_ixn.clone(),
                        vec![],
                    )
                    .await?;
                delegator.notify_witnesses().await?;

                // Query for receipts
                let query = delegator.query_mailbox(&delegator.id, &[witness_id_basic.clone()])?;

                for qry in query {
                    let signature = SelfSigningPrefix::Ed25519Sha512(km2.sign(&qry.encode()?)?);
                    let action_required = delegator.finalize_query(vec![(qry, signature)]).await?;
                    assert!(action_required.is_empty());
                }
                let data_signature = IndexedSignature::new_both_same(signature_ixn, 0);

                delegator
                    .finalize_exchange(&exn.encode()?, signature_exn, data_signature)
                    .await?;

                // ixn was accepted
                let delegators_state = controller2.storage.get_state(&delegator.id)?;
                assert_eq!(delegators_state.unwrap().sn, 1);
            }
        };
    }

    // Repeat query and expect 0 required actions.
    let query = delegator.query_mailbox(&delegator.id, &[witness_id_basic.clone()])?;
    for qry in query {
        let signature = SelfSigningPrefix::Ed25519Sha512(km2.sign(&qry.encode()?)?);
        let ar = delegator.finalize_query(vec![(qry, signature)]).await?;
        assert!(ar.is_empty());
    }

    // Process delegator's icp by identifier who'll request delegation.
    // TODO how child should get delegators kel?
    let delegators_kel = controller2
        .storage
        .get_kel_messages_with_receipts(&delegator.id, None)?
        .unwrap();
    controller.process(&Message::Notice(delegators_kel[0].clone()))?; // icp
    controller.process(&Message::Notice(delegators_kel[1].clone()))?; // receipt

    // Ask about delegated identifier mailbox
    let query = identifier1.query_mailbox(&delegate_id, &[witness_id_basic.clone()])?;

    for qry in query {
        let signature = SelfSigningPrefix::Ed25519Sha512(km1.sign(&qry.encode()?)?);
        let ar = identifier1.finalize_query(vec![(qry, signature)]).await?;
        assert!(ar.is_empty());
    }

    let state = identifier1.source.storage.get_state(&delegator.id)?;
    assert_eq!(state.unwrap().sn, 1);

    // Child kel is not yet accepted
    let state = identifier1.source.storage.get_state(&delegate_id)?;
    assert_eq!(state, None);

    // Get mailbox for receipts.
    let query = identifier1.query_mailbox(&delegate_id, &[witness_id_basic.clone()])?;

    for qry in query {
        let signature = SelfSigningPrefix::Ed25519Sha512(km1.sign(&qry.encode()?)?);
        let ar = identifier1.finalize_query(vec![(qry, signature)]).await?;
        assert!(ar.is_empty());
    }

    // Child kel is accepted
    let state = identifier1.source.storage.get_state(&delegate_id)?;
    assert_eq!(state.unwrap().sn, 0);

    Ok(())
}
