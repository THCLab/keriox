mod test_delegated_incept_postgres {
    mod common {
        include!("common/mod.rs");
    }

    use std::{collections::HashMap, sync::Arc};

    use keri_controller::{
        config::ControllerConfig, controller::PostgresController, error::ControllerError,
        mailbox_updating::ActionRequired, LocationScheme,
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
    async fn test_delegated_incept_postgres() -> Result<(), ControllerError> {
        use url::Url;

        common::ensure_clean_db();

        // Setup test witness (redb-backed — witness storage backend is independent)
        let witness = {
            let seed = "AK8F6AAiYDpXlWdj2O5F5-6wNCCNJh2A4XOlqwR_HwwH";
            let witness_root = Builder::new().prefix("test-wit1-db").tempdir().unwrap();
            Arc::new(
                WitnessListener::setup_with_redb(
                    Url::parse("http://witness1:3232/").unwrap(),
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

        let delegatee_root = Builder::new().prefix("test-db").tempdir().unwrap();
        let delegator_root = Builder::new().prefix("test-db2").tempdir().unwrap();

        // Setup delegatee identifier
        let delegatee_controller = Arc::new(
            PostgresController::new_postgres(
                &common::get_database_url(),
                ControllerConfig {
                    db_path: delegatee_root.path().to_owned(),
                    transport: Box::new(transport.clone()),
                    ..Default::default()
                },
            )
            .await?,
        );

        let delegatee_keypair = CryptoBox::new()?;
        let pk = BasicPrefix::Ed25519(delegatee_keypair.public_key());
        let npk = BasicPrefix::Ed25519(delegatee_keypair.next_public_key());

        let icp_event = delegatee_controller
            .incept(vec![pk], vec![npk], vec![wit_location.clone()], 1)
            .await?;
        let signature =
            SelfSigningPrefix::Ed25519Sha512(delegatee_keypair.sign(icp_event.as_bytes())?);

        let mut delegatee_identifier =
            delegatee_controller.finalize_incept(icp_event.as_bytes(), &signature)?;
        delegatee_identifier.notify_witnesses().await?;

        let query = delegatee_identifier
            .query_mailbox(delegatee_identifier.id(), &[witness_id_basic.clone()])?;
        for qry in query {
            let signature =
                SelfSigningPrefix::Ed25519Sha512(delegatee_keypair.sign(&qry.encode()?)?);
            delegatee_identifier
                .finalize_query_mailbox(vec![(qry, signature)])
                .await?;
        }

        // Setup delegator identifier
        let delegator_controller = Arc::new(
            PostgresController::new_postgres(
                &common::get_database_url(),
                ControllerConfig {
                    db_path: delegator_root.path().to_owned(),
                    transport: Box::new(transport.clone()),
                    ..Default::default()
                },
            )
            .await?,
        );

        let delegator_keypair = CryptoBox::new()?;
        let pk = BasicPrefix::Ed25519(delegator_keypair.public_key());
        let npk = BasicPrefix::Ed25519(delegator_keypair.next_public_key());

        let icp_event = delegator_controller
            .incept(vec![pk], vec![npk], vec![wit_location], 1)
            .await?;
        let signature =
            SelfSigningPrefix::Ed25519Sha512(delegator_keypair.sign(icp_event.as_bytes())?);

        let mut delegator =
            delegator_controller.finalize_incept(icp_event.as_bytes(), &signature)?;
        delegator.notify_witnesses().await?;

        let query = delegator.query_mailbox(&delegator.id(), &[witness_id_basic.clone()])?;
        for qry in query {
            let signature =
                SelfSigningPrefix::Ed25519Sha512(delegator_keypair.sign(&qry.encode()?)?);
            let ar = delegator
                .finalize_query_mailbox(vec![(qry, signature)])
                .await?;
            assert!(ar.is_empty());
        }

        // Generate delegated inception
        let (delegated_inception, exn_messages) = delegatee_identifier.incept_group(
            vec![],
            1,
            Some(1),
            Some(vec![witness_id_basic.clone()]),
            Some(1),
            Some(delegator.id().clone()),
        )?;

        let signature_icp = SelfSigningPrefix::Ed25519Sha512(
            delegatee_keypair.sign(delegated_inception.as_bytes())?,
        );
        let signature_exn =
            SelfSigningPrefix::Ed25519Sha512(delegatee_keypair.sign(exn_messages[0].as_bytes())?);
        let exn_index_signature = delegatee_identifier.sign_with_index(signature_exn, 0)?;

        let delegate_id = delegatee_identifier
            .finalize_group_incept(
                delegated_inception.as_bytes(),
                signature_icp.clone(),
                vec![(exn_messages[0].as_bytes().to_vec(), exn_index_signature)],
            )
            .await?;

        let kel = delegatee_controller.get_kel_with_receipts(&delegate_id);
        assert!(kel.is_none());

        let query = delegator.query_mailbox(delegator.id(), &[witness_id_basic.clone()])?;
        for qry in query {
            let signature =
                SelfSigningPrefix::Ed25519Sha512(delegator_keypair.sign(&qry.encode()?)?);
            let ar = delegator
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
                    let exn_index_signature = delegator.sign_with_index(signature_exn, 0).unwrap();
                    delegator
                        .finalize_group_event(
                            &delegating_event.encode()?,
                            signature_ixn.clone(),
                            vec![],
                        )
                        .await?;
                    delegator.notify_witnesses().await?;

                    let query =
                        delegator.query_mailbox(delegator.id(), &[witness_id_basic.clone()])?;
                    for qry in query {
                        let signature = SelfSigningPrefix::Ed25519Sha512(
                            delegator_keypair.sign(&qry.encode()?)?,
                        );
                        let action_required = delegator
                            .finalize_query_mailbox(vec![(qry, signature)])
                            .await?;
                        assert!(action_required.is_empty());
                    }

                    let data_signature = IndexedSignature::new_both_same(signature_ixn, 0);
                    delegator
                        .finalize_exchange(&exn.encode()?, exn_index_signature, data_signature)
                        .await?;

                    let delegators_state = delegator_controller.find_state(delegator.id())?;
                    assert_eq!(delegators_state.sn, 1);
                }
            };
        }

        let query = delegator.query_mailbox(delegator.id(), &[witness_id_basic.clone()])?;
        for qry in query {
            let signature =
                SelfSigningPrefix::Ed25519Sha512(delegator_keypair.sign(&qry.encode()?)?);
            let ar = delegator
                .finalize_query_mailbox(vec![(qry, signature)])
                .await?;
            assert_eq!(ar.len(), 0);
        }

        let delegators_kel = delegator_controller
            .get_kel_with_receipts(&delegator.id())
            .unwrap();
        delegatee_controller
            .known_events
            .save(&Message::Notice(delegators_kel[0].clone()))?;

        let query =
            delegatee_identifier.query_mailbox(&delegate_id, &[witness_id_basic.clone()])?;
        for qry in query {
            let signature =
                SelfSigningPrefix::Ed25519Sha512(delegatee_keypair.sign(&qry.encode()?)?);
            let ar = delegatee_identifier
                .finalize_query_mailbox(vec![(qry, signature)])
                .await?;
            assert!(ar.is_empty())
        }

        let state = delegatee_identifier.find_state(delegator.id())?;
        assert_eq!(state.sn, 1);

        let state = delegatee_identifier.find_state(&delegate_id);
        assert!(state.is_err());

        let query =
            delegatee_identifier.query_mailbox(&delegate_id, &[witness_id_basic.clone()])?;
        for qry in query {
            let signature =
                SelfSigningPrefix::Ed25519Sha512(delegatee_keypair.sign(&qry.encode()?)?);
            let ar = delegatee_identifier
                .finalize_query_mailbox(vec![(qry, signature)])
                .await?;
            assert!(ar.is_empty());
        }

        let state = delegatee_identifier.find_state(&delegate_id)?;
        assert_eq!(state.sn, 0);

        Ok(())
    }
}
