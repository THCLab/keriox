#![cfg(test)]

use std::{collections::HashMap, sync::Arc};

use keri::{
    actor::{error::ActorError, prelude::Message, SignedQueryError},
    event::event_data::EventData,
    event_message::signed_event_message::Notice,
    oobi::LocationScheme,
    prefix::{AttachedSignaturePrefix, BasicPrefix, IdentifierPrefix, SelfSigningPrefix},
    signer::{CryptoBox, KeyManager},
    transport::{
        test::{TestActorMap, TestTransport},
        TransportError,
    },
};
use tempfile::Builder;
use url::Host;
use witness::WitnessListener;

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
        let pk = BasicPrefix::Ed25519(km1.public_key());
        let npk = BasicPrefix::Ed25519(km1.next_public_key());

        let icp_event = controller.incept(vec![pk], vec![npk], vec![], 0).await?;
        let signature = SelfSigningPrefix::Ed25519Sha512(km1.sign(icp_event.as_bytes())?);

        let incepted_identifier = controller
            .finalize_inception(icp_event.as_bytes(), &signature)
            .await?;
        IdentifierController::new(incepted_identifier, controller.clone())
    };
    identifier1.notify_witnesses().await?;

    let identifier2 = {
        let pk = BasicPrefix::Ed25519(km2.public_key());
        let npk = BasicPrefix::Ed25519(km2.next_public_key());

        let icp_event = controller.incept(vec![pk], vec![npk], vec![], 0).await?;
        let signature = SelfSigningPrefix::Ed25519Sha512(km2.sign(icp_event.as_bytes())?);

        let incepted_identifier = controller
            .finalize_inception(icp_event.as_bytes(), &signature)
            .await?;
        IdentifierController::new(incepted_identifier, controller.clone())
    };
    identifier2.notify_witnesses().await?;

    let (group_inception, exn_messages) =
        identifier1.incept_group(vec![identifier2.id.clone()], 2, None, None, None)?;

    let signature_icp = SelfSigningPrefix::Ed25519Sha512(km1.sign(group_inception.as_bytes())?);
    let signature_exn = SelfSigningPrefix::Ed25519Sha512(km1.sign(exn_messages[0].as_bytes())?);

    // Group initiator needs to use `finalize_group_incept` instead of just
    // `finalize_event`, to send multisig request to other group participants.
    // Identifier who get this request from mailbox, can use just `finalize_event`
    let group_id = identifier1
        .finalize_group_incept(
            group_inception.as_bytes(),
            signature_icp,
            vec![(exn_messages[0].as_bytes().to_vec(), signature_exn)],
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
    let signature_icp = SelfSigningPrefix::Ed25519Sha512(km2.sign(group_inception.as_bytes())?);
    identifier2
        .finalize_event(group_inception.as_bytes(), signature_icp)
        .await?;

    let kel = controller
        .storage
        .get_kel_messages_with_receipts(&group_id)?;
    assert!(kel.is_some());

    Ok(())
}

#[ignore]
#[async_std::test]
async fn test_delegated_incept() -> Result<(), ControllerError> {
    use url::Url;
    let root = Builder::new().prefix("test-db").tempdir().unwrap();
    let root2 = Builder::new().prefix("test-db2").tempdir().unwrap();
    let initial_config = OptionalConfig::init().with_db_path(root.into_path());
    let initial_config2 = OptionalConfig::init().with_db_path(root2.into_path());

    let witness = {
        let seed = "AK8F6AAiYDpXlWdj2O5F5-6wNCCNJh2A4XOlqwR_HwwH";
        let witness_root = Builder::new().prefix("test-wit1-db").tempdir().unwrap();
        Arc::new(WitnessListener::setup(
            url::Url::parse("http://witness1:3232/").unwrap(), // not used
            None,
            witness_root.path(),
            Some(seed.to_string()),
        )?)
    };

    let witness_id_basic = witness.get_prefix();
    let witness_id = IdentifierPrefix::Basic(witness_id_basic.clone());
    assert_eq!(
        witness_id.to_string(),
        "BErocgXD2RGSyvn3MObcx59jeOsEQhv2TqHirVkzrp0Q"
    );
    let wit_location = LocationScheme {
        eid: witness_id,
        scheme: keri::oobi::Scheme::Http,
        url: Url::parse("http://witness1:3232").unwrap(),
    };

    let mut actors: TestActorMap = HashMap::new();
    actors.insert((Host::Domain("witness1".to_string()), 3232), witness);
    let transport = TestTransport::new(actors);

    let controller = Arc::new(Controller::with_transport(
        Some(initial_config),
        Box::new(transport.clone()),
    )?);
    let controller2 = Arc::new(Controller::with_transport(
        Some(initial_config2),
        Box::new(transport),
    )?);
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
        IdentifierController::new(incepted_identifier, controller.clone())
    };
    identifier1.notify_witnesses().await?;

    // Quering mailbox to get receipts
    let query = identifier1.query_mailbox(&identifier1.id, &[witness_id_basic.clone()])?;

    // Query with wrong signature
    {
        let qry = query[0].clone();
        let sig = SelfSigningPrefix::Ed25519Sha512(km2.sign(&qry.serialize()?)?);
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
        let signature = SelfSigningPrefix::Ed25519Sha512(km1.sign(&qry.serialize()?)?);
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
        IdentifierController::new(incepted_identifier, controller2.clone())
    };
    delegator.notify_witnesses().await?;

    // Quering mailbox to get receipts
    let query = delegator.query_mailbox(&delegator.id, &[witness_id_basic.clone()])?;

    for qry in query {
        let signature = SelfSigningPrefix::Ed25519Sha512(km2.sign(&qry.serialize()?)?);
        delegator.finalize_query(vec![(qry, signature)]).await?;
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
                keri::error::Error::SignatureVerificationError
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

    for qry in query {
        let signature = SelfSigningPrefix::Ed25519Sha512(km2.sign(&qry.serialize()?)?);
        delegator.finalize_query(vec![(qry, signature)]).await?;
    }
    let data_signature = AttachedSignaturePrefix::new(signature_icp, 0);

    identifier1
        .finalize_exchange(exn_messages[0].as_bytes(), signature_exn, data_signature)
        .await?;

    println!("before get_kel_messages_with_receipts");
    let kel = controller
        .storage
        .get_kel_messages_with_receipts(&delegate_id)?;
    // Event is not yet accepted. Missing delegating event.
    println!("after get_kel_messages_with_receipts");
    assert!(kel.is_none());

    // Delegator asks about his mailbox to get delegated event.
    let query = delegator.query_mailbox(&delegator.id, &[witness_id_basic.clone()])?;

    for qry in query {
        let signature = SelfSigningPrefix::Ed25519Sha512(km2.sign(&qry.serialize()?)?);
        let ar = delegator.finalize_query(vec![(qry, signature)]).await?;
        assert_eq!(ar.len(), 1);
        match &ar[0] {
            ActionRequired::MultisigRequest(_, _) => unreachable!(),
            ActionRequired::DelegationRequest(delegating_event, exn) => {
                let signature_ixn =
                    SelfSigningPrefix::Ed25519Sha512(km2.sign(&delegating_event.serialize()?)?);
                let signature_exn = SelfSigningPrefix::Ed25519Sha512(km2.sign(&exn.serialize()?)?);
                delegator
                    .finalize_group_incept(
                        &delegating_event.serialize()?,
                        signature_ixn.clone(),
                        vec![],
                    )
                    .await?;

                // Query for receipts
                let query = delegator.query_mailbox(&delegator.id, &[witness_id_basic.clone()])?;

                for qry in query {
                    let signature = SelfSigningPrefix::Ed25519Sha512(km2.sign(&qry.serialize()?)?);
                    let action_required = delegator.finalize_query(vec![(qry, signature)]).await?;
                    assert!(action_required.is_empty());
                }
                let data_signature = AttachedSignaturePrefix::new(signature_ixn, 0);

                delegator
                    .finalize_exchange(&exn.serialize()?, signature_exn, data_signature)
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

    // Ask about delegated identifier mailbox
    let query = identifier1.query_mailbox(&delegate_id, &[witness_id_basic.clone()])?;

    for qry in query {
        let signature = SelfSigningPrefix::Ed25519Sha512(km1.sign(&qry.serialize()?)?);
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
        let signature = SelfSigningPrefix::Ed25519Sha512(km1.sign(&qry.serialize()?)?);
        let ar = identifier1.finalize_query(vec![(qry, signature)]).await?;
        assert!(ar.is_empty());
    }

    // Child kel is accepted
    let state = identifier1.source.storage.get_state(&delegate_id)?;
    assert_eq!(state.unwrap().sn, 0);

    Ok(())
}

#[async_std::test]
async fn test_2_wit() -> Result<(), ControllerError> {
    use url::Url;
    let root = Builder::new().prefix("test-db").tempdir().unwrap();
    let initial_config = OptionalConfig::init().with_db_path(root.into_path());

    let witness1 = {
        let seed = "AK8F6AAiYDpXlWdj2O5F5-6wNCCNJh2A4XOlqwR_HwwH";
        let witness_root = Builder::new().prefix("test-wit1-db").tempdir().unwrap();
        Arc::new(WitnessListener::setup(
            url::Url::parse("http://witness1/").unwrap(), // not used
            None,
            witness_root.path(),
            Some(seed.to_string()),
        )?)
    };
    let witness2 = {
        let seed = "AJZ7ZLd7unQ4IkMUwE69NXcvDO9rrmmRH_Xk3TPu9BpP";
        let witness_root = Builder::new().prefix("test-wit2-db").tempdir().unwrap();
        Arc::new(WitnessListener::setup(
            url::Url::parse("http://witness2/").unwrap(), // not used
            None,
            witness_root.path(),
            Some(seed.to_string()),
        )?)
    };

    let wit1_id = witness1.get_prefix();
    let wit1_location = LocationScheme {
        eid: IdentifierPrefix::Basic(wit1_id.clone()),
        scheme: keri::oobi::Scheme::Http,
        url: Url::parse("http://witness1/").unwrap(),
    };
    let wit2_id = witness2.get_prefix();
    let wit2_location = LocationScheme {
        eid: IdentifierPrefix::Basic(wit2_id.clone()),
        scheme: keri::oobi::Scheme::Http,
        url: Url::parse("http://witness2/").unwrap(),
    };

    let mut actors: TestActorMap = HashMap::new();
    actors.insert((Host::Domain("witness1".to_string()), 80), witness1.clone());
    actors.insert((Host::Domain("witness2".to_string()), 80), witness2.clone());
    let transport = TestTransport::new(actors);

    let controller = Arc::new(Controller::with_transport(
        Some(initial_config),
        Box::new(transport.clone()),
    )?);

    let km1 = CryptoBox::new()?;

    let mut ident_ctl = {
        let pk = BasicPrefix::Ed25519(km1.public_key());
        let npk = BasicPrefix::Ed25519(km1.next_public_key());

        let icp_event = controller
            .incept(
                vec![pk],
                vec![npk],
                vec![wit1_location.clone(), wit2_location.clone()],
                2,
            )
            .await?;
        let signature = SelfSigningPrefix::Ed25519Sha512(km1.sign(icp_event.as_bytes())?);

        let incepted_identifier = controller
            .finalize_inception(icp_event.as_bytes(), &signature)
            .await?;
        IdentifierController::new(incepted_identifier, controller.clone())
    };

    let n = ident_ctl.notify_witnesses().await.unwrap();
    assert_eq!(n, 1);

    // Quering mailbox to get receipts
    let query = ident_ctl.query_mailbox(&ident_ctl.id, &[wit1_id.clone(), wit2_id.clone()])?;

    for qry in query {
        let signature = SelfSigningPrefix::Ed25519Sha512(km1.sign(&qry.serialize()?)?);
        ident_ctl.finalize_query(vec![(qry, signature)]).await?;
    }

    let n = ident_ctl.notify_witnesses().await.unwrap();
    assert_eq!(n, 0);

    let n = ident_ctl
        .broadcast_receipts(&[
            IdentifierPrefix::Basic(wit1_id.clone()),
            IdentifierPrefix::Basic(wit2_id.clone()),
        ])
        .await?;
    assert_eq!(n, 2);

    let kel = witness1
        .witness_data
        .event_storage
        .get_kel_messages_with_receipts(&ident_ctl.id)
        .unwrap()
        .unwrap();
    assert_eq!(kel.len(), 2);

    match &kel[0] {
        Notice::Event(evt) => match evt.event_message.event.content.event_data {
            EventData::Icp(_) => (),
            _ => panic!("Unexpected event type"),
        },
        _ => panic!("Unexpected notice type"),
    }

    match &kel[1] {
        Notice::NontransferableRct(rct) => {
            // TODO: fix witness to not insert duplicate signatures
            assert_eq!(rct.signatures.len(), 3);
        }
        _ => panic!("Unexpected notice type"),
    }

    Ok(())
}
