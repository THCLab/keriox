use std::sync::Arc;

use keri_controller::{
    config::ControllerConfig, error::ControllerError, identifier_controller::IdentifierController,
    BasicPrefix, Controller, CryptoBox, KeyManager, LocationScheme, SelfSigningPrefix,
};
use tempfile::Builder;

#[async_std::test]
async fn test_kel_with_witness() -> Result<(), ControllerError> {
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
    let controller = Arc::new(Controller::new(ControllerConfig {
        db_path: database_path.path().to_owned(),
        ..Default::default()
    })?);

    // Incept identifier.
    // The `IdentifierController` structure facilitates the management of the
    // Key Event Log specific to a particular identifier.
    let actor = {
        let pk = BasicPrefix::Ed25519(key_manager.public_key());
        let npk = BasicPrefix::Ed25519(key_manager.next_public_key());

        // Create inception event, that needs one witness receipt to be accepted.
        let icp_event = controller
            .incept(
                vec![pk],
                vec![npk],
                vec![first_witness_oobi, second_witness_oobi],
                1,
            )
            .await?;
        let signature =
            SelfSigningPrefix::Ed25519Sha512(key_manager.sign(icp_event.as_bytes()).unwrap());

        let identifier = controller
            .finalize_inception(icp_event.as_bytes(), &signature)
            .await?;
        IdentifierController::new(identifier, controller.clone(), None)
    };

    // The Event Seal specifies the stage of KEL at the time of signature creation.
    // This enables us to retrieve the correct public keys from KEL during verification.
    // Trying to get current actor event seal.
    let inception_event_seal = actor.get_last_establishment_event_seal();

    // It fails because witness receipts are missing.
    assert!(matches!(
        inception_event_seal,
        Err(ControllerError::UnknownIdentifierError)
    ));

    // Publish event to actor's witnesses
    actor.notify_witnesses().await.unwrap();

    // Querying witness to get receipts
    for qry in actor
        .query_mailbox(&actor.id, &[first_witness_id.clone()])
        .unwrap()
    {
        let signature =
            SelfSigningPrefix::Ed25519Sha512(key_manager.sign(&qry.encode().unwrap()).unwrap());
        actor.finalize_query(vec![(qry, signature)]).await.unwrap();
    }

    // Now KEL event should be accepted and event seal exists.
    let inception_event_seal = actor.get_last_establishment_event_seal();
    assert!(inception_event_seal.is_ok());

    // Sign message with established identifier
    let first_message = "Hi".as_bytes();
    let first_message_signature = vec![SelfSigningPrefix::Ed25519Sha512(
        key_manager.sign(first_message).unwrap(),
    )];

    let signature = actor.transferable_signature(
        first_message,
        inception_event_seal?,
        &first_message_signature,
    )?;

    assert!(controller.verify(first_message, &signature).is_ok());

    // Rotate keys
    key_manager.rotate()?;
    let pk = BasicPrefix::Ed25519(key_manager.public_key());
    let npk = BasicPrefix::Ed25519(key_manager.next_public_key());

    // Rotation needs two witness receipts to be accepted
    let rotation_event = actor.rotate(vec![pk], vec![npk], vec![], vec![], 2).await?;

    let signature = SelfSigningPrefix::Ed25519Sha512(key_manager.sign(rotation_event.as_bytes())?);
    actor
        .finalize_event(rotation_event.as_bytes(), signature)
        .await?;

    // Trying to verify message signed with rotated keys.
    let message = "Hi".as_bytes();
    let first_message_signature = vec![SelfSigningPrefix::Ed25519Sha512(
        key_manager.sign(message).unwrap(),
    )];

    let current_event_seal = actor.get_last_establishment_event_seal()?;
    let signature =
        actor.transferable_signature(message, current_event_seal, &first_message_signature)?;

    // Verification fails. Rotation wasn't accepted into KEL because of lack of
    // witness receipts. Current event seal points to inception event so old
    // public keys are used for verification.
    assert!(matches!(
        controller.verify(message, &signature).unwrap_err(),
        ControllerError::FaultySignature
    ));

    // Publish event to actor's witnesses
    actor.notify_witnesses().await.unwrap();

    // Querying witnesses to get receipts
    for qry in actor
        .query_mailbox(&actor.id, &[first_witness_id, second_witness_id])
        .unwrap()
    {
        let signature =
            SelfSigningPrefix::Ed25519Sha512(key_manager.sign(&qry.encode().unwrap()).unwrap());
        actor.finalize_query(vec![(qry, signature)]).await.unwrap();
    }

    // Update signature and verify again
    let current_event_seal = actor.get_last_establishment_event_seal()?;
    let signature =
        actor.transferable_signature(message, current_event_seal, &first_message_signature)?;

    assert!(controller.verify(message, &signature).is_ok());

    Ok(())
}
