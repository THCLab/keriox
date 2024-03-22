use std::sync::Arc;

use keri_controller::{
    config::ControllerConfig, error::ControllerError, identifier_controller::IdentifierController,
    BasicPrefix, Controller, CryptoBox, EndRole, IdentifierPrefix, KeyManager, LocationScheme,
    Oobi, SelfSigningPrefix,
};
use tempfile::Builder;

#[async_std::test]
async fn indirect_mode_signing() -> Result<(), ControllerError> {
    let first_witness_id: BasicPrefix = "BDg3H7Sr-eES0XWXiO8nvMxW6mD_1LxLeE1nuiZxhGp4"
        .parse()
        .unwrap();
    // OOBI (Out-Of-Band Introduction) specifies the way how actors can be found.
    let first_witness_oobi: LocationScheme = serde_json::from_str(&format!(
        r#"{{"eid":{:?},"scheme":"http","url":"http://witness2.sandbox.argo.colossi.network/"}}"#,
        first_witness_id
    ))
    .unwrap();

    let second_witness_id: BasicPrefix = "BDg1zxxf8u4Hx5IPraZzmStfSCZFZbDzMHjqVcFW5OfP"
        .parse()
        .unwrap();
    let second_witness_oobi: LocationScheme = serde_json::from_str(&format!(
        r#"{{"eid":{:?},"scheme":"http","url":"http://witness3.sandbox.argo.colossi.network/"}}"#,
        second_witness_id
    ))
    .unwrap();

    // Setup database path and key manager.
    let database_path = Builder::new().prefix("test-db0").tempdir().unwrap();
    let mut key_manager = CryptoBox::new().unwrap();

    // The `Controller` structure aggregates all known KEL events (across all
    // identifiers) and offers functions for retrieving them, verifying the
    // integrity of new events, and conducting signature verification.
    let signing_controller = Arc::new(Controller::new(ControllerConfig {
        db_path: database_path.path().to_owned(),
        ..Default::default()
    })?);

    // Incept identifier.
    // The `IdentifierController` structure facilitates the management of the
    // Key Event Log specific to a particular identifier.
    let signing_identifier: IdentifierController = {
        let pk = BasicPrefix::Ed25519(key_manager.public_key());
        let npk = BasicPrefix::Ed25519(key_manager.next_public_key());

        // Create inception event, that needs one witness receipt to be accepted.
        let icp_event = signing_controller
            .incept(
                vec![pk],
                vec![npk],
                vec![first_witness_oobi.clone(), second_witness_oobi.clone()],
                1,
            )
            .await?;
        let signature =
            SelfSigningPrefix::Ed25519Sha512(key_manager.sign(icp_event.as_bytes()).unwrap());

        let identifier = signing_controller
            .finalize_inception(icp_event.as_bytes(), &signature)
            .await?;
        IdentifierController::new(identifier, signing_controller.clone(), None)
    };

    // The Event Seal specifies the stage of KEL at the time of signature creation.
    // This enables us to retrieve the correct public keys from KEL during verification.
    // Trying to get current actor event seal.
    let inception_event_seal = signing_identifier.get_last_establishment_event_seal();

    // It fails because witness receipts are missing.
    assert!(matches!(
        inception_event_seal,
        Err(ControllerError::UnknownIdentifierError)
    ));

    // Publish event to actor's witnesses
    signing_identifier.notify_witnesses().await.unwrap();

    // Querying witness to get receipts
    for qry in signing_identifier
        .query_mailbox(&signing_identifier.id, &[first_witness_id.clone()])
        .unwrap()
    {
        let signature =
            SelfSigningPrefix::Ed25519Sha512(key_manager.sign(&qry.encode().unwrap()).unwrap());
        signing_identifier
            .finalize_query(vec![(qry, signature)])
            .await
            .unwrap();
    }

    // Now KEL event should be accepted and event seal exists.
    let inception_event_seal = signing_identifier.get_last_establishment_event_seal();
    assert!(inception_event_seal.is_ok());

    // Rotate signer keys
    key_manager.rotate()?;
    let pk = BasicPrefix::Ed25519(key_manager.public_key());
    let npk = BasicPrefix::Ed25519(key_manager.next_public_key());

    // Rotation needs two witness receipts to be accepted
    let rotation_event = signing_identifier
        .rotate(vec![pk], vec![npk], vec![], vec![], 2)
        .await?;

    let signature = SelfSigningPrefix::Ed25519Sha512(key_manager.sign(rotation_event.as_bytes())?);
    signing_identifier
        .finalize_event(rotation_event.as_bytes(), signature)
        .await?;

    // Publish event to actor's witnesses
    signing_identifier.notify_witnesses().await.unwrap();

    // Querying witnesses to get receipts
    for qry in signing_identifier
        .query_mailbox(
            &signing_identifier.id,
            &[first_witness_id.clone(), second_witness_id.clone()],
        )
        .unwrap()
    {
        let signature =
            SelfSigningPrefix::Ed25519Sha512(key_manager.sign(&qry.encode().unwrap()).unwrap());
        signing_identifier
            .finalize_query(vec![(qry, signature)])
            .await
            .unwrap();
    }

    // Sign message with rotated keys.
    let message = "Hi".as_bytes();
    let first_message_signature = vec![SelfSigningPrefix::Ed25519Sha512(
        key_manager.sign(message).unwrap(),
    )];

    let current_event_seal = signing_identifier.get_last_establishment_event_seal()?;
    let message_signature = signing_identifier.transferable_signature(
        message,
        current_event_seal,
        &first_message_signature,
    )?;

    // Establish verifying identifier
    // Setup database path and key manager.
    let verifier_database_path = Builder::new().prefix("test-db0").tempdir().unwrap();
    let verifier_key_manager = CryptoBox::new().unwrap();

    let verifying_controller = Arc::new(Controller::new(ControllerConfig {
        db_path: verifier_database_path.path().to_owned(),
        ..Default::default()
    })?);

    let verifying_identifier: IdentifierController = {
        let pk = BasicPrefix::Ed25519(verifier_key_manager.public_key());
        let npk = BasicPrefix::Ed25519(verifier_key_manager.next_public_key());

        // Create inception event, that needs one witness receipt to be accepted.
        let icp_event = verifying_controller
            .incept(
                vec![pk],
                vec![npk],
                vec![first_witness_oobi.clone(), second_witness_oobi.clone()],
                1,
            )
            .await?;
        let signature = SelfSigningPrefix::Ed25519Sha512(
            verifier_key_manager.sign(icp_event.as_bytes()).unwrap(),
        );

        let identifier = verifying_controller
            .finalize_inception(icp_event.as_bytes(), &signature)
            .await?;
        IdentifierController::new(identifier, verifying_controller.clone(), None)
    };

    // Publish event to actor's witnesses
    verifying_identifier.notify_witnesses().await.unwrap();

    // Querying witness to get receipts
    for qry in verifying_identifier
        .query_mailbox(&verifying_identifier.id, &[first_witness_id.clone()])
        .unwrap()
    {
        let signature = SelfSigningPrefix::Ed25519Sha512(
            verifier_key_manager.sign(&qry.encode().unwrap()).unwrap(),
        );
        verifying_identifier
            .finalize_query(vec![(qry, signature)])
            .await
            .unwrap();
    }

    // Check if verifying identifier was established successfully
    let inception_event_seal = verifying_identifier.get_last_establishment_event_seal();
    assert!(inception_event_seal.is_ok());

    // Now setup watcher, to be able to query it of signing identifier's KEL.
    let watcher_id: IdentifierPrefix = "BF2t2NPc1bwptY1hYV0YCib1JjQ11k9jtuaZemecPF5b"
        .parse()
        .unwrap();
    let watcher_oobi: LocationScheme = serde_json::from_str(&format!(
        r#"{{"eid":"{}","scheme":"http","url":"http://watcher.sandbox.argo.colossi.network/"}}"#,
        watcher_id
    ))
    .unwrap();

    // Resolve watcher oobi
    verifying_identifier
        .source
        .resolve_loc_schema(&watcher_oobi)
        .await?;

    // Setup watcher. Generate and sign event, that will be sent to watcher, so
    // it knows to act as verifier's watcher.
    let add_watcher = verifying_identifier.add_watcher(watcher_id)?;
    let signature = SelfSigningPrefix::Ed25519Sha512(
        verifier_key_manager.sign(add_watcher.as_bytes()).unwrap(),
    );

    verifying_identifier
        .finalize_event(add_watcher.as_bytes(), signature)
        .await?;

    // Try to verify signed message. It fails, because verifying identifier
    // doesn't know signing identifier yet.
    assert!(matches!(
        verifying_controller.verify(message, &message_signature),
        Err(ControllerError::MissingEventError)
    ));

    // Now query watcher about signer's KEL.
    // To find `signing_identifier`s KEL, `verifying_identifier` needs to
    // provide to watcher its oobi and oobi of its witnesses.
    let witnesses_oobi = vec![first_witness_oobi, second_witness_oobi];

    for wit_oobi in witnesses_oobi {
        let oobi = Oobi::Location(wit_oobi);

        verifying_identifier
            .source
            .send_oobi_to_watcher(&signing_identifier.id.clone(), &oobi)
            .await?;
    }
    let signer_oobi = EndRole {
        cid: signing_identifier.id.clone(),
        role: keri_core::oobi::Role::Witness,
        eid: keri_controller::IdentifierPrefix::Basic(second_witness_id.clone()),
    };

    verifying_identifier
        .source
        .send_oobi_to_watcher(
            &verifying_identifier.id.clone(),
            &Oobi::EndRole(signer_oobi),
        )
        .await?;

    // Query KEL of signing identifier. Generate query events and sign them.
    let queries_and_signatures: Vec<_> = verifying_identifier
        .query_own_watchers(&signing_identifier.id)?
        .into_iter()
        .map(|qry| {
            let signature = SelfSigningPrefix::Ed25519Sha512(
                verifier_key_manager.sign(&qry.encode().unwrap()).unwrap(),
            );
            (qry, signature)
        })
        .collect();

    let mut query_result = verifying_identifier
        .finalize_query(queries_and_signatures.clone())
        .await;

    // Watcher might need some time to find KEL. Ask about it until it's ready.
    while query_result.is_err() {
        query_result = verifying_identifier
            .finalize_query(queries_and_signatures.clone())
            .await;
    }

    // Verify signed message.
    assert!(verifying_controller
        .verify(message, &message_signature)
        .is_ok());

    Ok(())
}
