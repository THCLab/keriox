use std::sync::Arc;

use keri_controller::{
    config::ControllerConfig, error::ControllerError, identifier_controller::IdentifierController,
    BasicPrefix, Controller, CryptoBox, KeyManager, SelfSigningPrefix,
};
use tempfile::Builder;

#[async_std::test]
async fn test_single_key_identifier() -> Result<(), ControllerError> {
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

        // Create inception event.
        let icp_event = controller
            .incept(vec![pk], vec![npk], vec![], 0)
            .await
            .unwrap();
        let signature =
            SelfSigningPrefix::Ed25519Sha512(key_manager.sign(icp_event.as_bytes()).unwrap());

        // Provide signature to finalize inception.
        let incepted_identifier = controller
            .finalize_inception(icp_event.as_bytes(), &signature)
            .await
            .unwrap();
        IdentifierController::new(incepted_identifier, controller.clone(), None)
    };

    // Sign message with established identifier
    let first_message = "Hi".as_bytes();
    let first_message_signature = vec![SelfSigningPrefix::Ed25519Sha512(
        key_manager.sign(first_message).unwrap(),
    )];

    // The Event Seal specifies the stage of KEL at the time of signature creation.
    // This enables us to retrieve the correct public keys from KEL during verification.
    let inception_event_seal = actor.get_last_establishment_event_seal()?;
    let signature = actor.transferable_signature(
        first_message,
        inception_event_seal,
        &first_message_signature,
    )?;

    assert!(controller.verify(first_message, &signature).is_ok());

    // Rotate keys
    key_manager.rotate()?;
    let pk = BasicPrefix::Ed25519(key_manager.public_key());
    let npk = BasicPrefix::Ed25519(key_manager.next_public_key());

    let rotation_event = actor.rotate(vec![pk], vec![npk], vec![], vec![], 0).await?;

    let signature = SelfSigningPrefix::Ed25519Sha512(key_manager.sign(rotation_event.as_bytes())?);
    actor
        .finalize_event(rotation_event.as_bytes(), signature)
        .await?;

    let second_message = "Second message".as_bytes();
    let second_message_signatures = vec![SelfSigningPrefix::Ed25519Sha512(
        key_manager.sign(second_message).unwrap(),
    )];

    let rotation_event_seal = actor.get_last_establishment_event_seal()?;
    let signature = actor.transferable_signature(
        second_message,
        rotation_event_seal,
        &second_message_signatures,
    )?;

    assert!(controller.verify(second_message, &signature).is_ok());

    Ok(())
}
