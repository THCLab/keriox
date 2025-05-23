use std::{sync::Arc, time::Duration};

use actix_rt::time::sleep;
use keri_controller::{
    config::ControllerConfig, controller::Controller, error::ControllerError,
    identifier::query::QueryResponse, BasicPrefix, CryptoBox, EndRole, IdentifierPrefix,
    KeyManager, Oobi, SelfSigningPrefix,
};
use keri_core::processor::validator::{MoreInfoError, VerificationError};
use keri_tests::settings::InfrastructureContext;
use tempfile::Builder;
use test_context::test_context;

#[test_context(InfrastructureContext)]
#[actix_rt::test]
async fn test_updates(ctx: &mut InfrastructureContext) -> Result<(), ControllerError> {
    let (first_witness_id, first_witness_oobi) = ctx.first_witness_data();
    let (second_witness_id, second_witness_oobi) = ctx.second_witness_data();

    // Setup signing identifier.
    let database_path = Builder::new().prefix("test-db0").tempdir().unwrap();
    let mut key_manager = CryptoBox::new().unwrap();

    let signer_controller = Arc::new(Controller::new(ControllerConfig {
        db_path: database_path.path().to_owned(),
        ..Default::default()
    })?);

    let pk = BasicPrefix::Ed25519(key_manager.public_key());
    let npk = BasicPrefix::Ed25519(key_manager.next_public_key());

    // Create inception event, that needs one witness receipt to be accepted.
    let icp_event = signer_controller
        .incept(
            vec![pk],
            vec![npk],
            vec![first_witness_oobi.clone(), second_witness_oobi.clone()],
            1,
        )
        .await?;
    let signature =
        SelfSigningPrefix::Ed25519Sha512(key_manager.sign(icp_event.as_bytes()).unwrap());

    let mut signing_identifier =
        signer_controller.finalize_incept(icp_event.as_bytes(), &signature)?;

    println!("Signer: {}", &signing_identifier.id());

    // Publish event to actor's witnesses
    signing_identifier.notify_witnesses().await.unwrap();

    // Querying witness to get receipts
    for qry in signing_identifier
        .query_mailbox(signing_identifier.id(), &[first_witness_id.clone()])
        .unwrap()
    {
        let signature =
            SelfSigningPrefix::Ed25519Sha512(key_manager.sign(&qry.encode().unwrap()).unwrap());
        signing_identifier
            .finalize_query_mailbox(vec![(qry, signature)])
            .await
            .unwrap();
    }

    // Sign message with established identifier
    let first_message = "Hi".as_bytes();
    let first_message_signature = vec![SelfSigningPrefix::Ed25519Sha512(
        key_manager.sign(first_message).unwrap(),
    )];

    let first_signature = signing_identifier
        .sign_data(first_message, &first_message_signature)
        .unwrap();

    // Establish verifying identifier
    let verifier_database_path = Builder::new().prefix("test-db1").tempdir().unwrap();
    let verifier_key_manager = CryptoBox::new().unwrap();

    let verifying_controller = Arc::new(Controller::new(ControllerConfig {
        db_path: verifier_database_path.path().to_owned(),
        ..Default::default()
    })?);

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
    let signature =
        SelfSigningPrefix::Ed25519Sha512(verifier_key_manager.sign(icp_event.as_bytes()).unwrap());

    let mut verifying_identifier =
        verifying_controller.finalize_incept(icp_event.as_bytes(), &signature)?;

    println!("Verifier: {}", verifying_identifier.id());

    // Publish event to actor's witnesses
    verifying_identifier.notify_witnesses().await.unwrap();

    // Querying witness to get receipts
    for qry in verifying_identifier
        .query_mailbox(verifying_identifier.id(), &[first_witness_id.clone()])
        .unwrap()
    {
        let signature = SelfSigningPrefix::Ed25519Sha512(
            verifier_key_manager.sign(&qry.encode().unwrap()).unwrap(),
        );
        verifying_identifier
            .finalize_query_mailbox(vec![(qry, signature)])
            .await
            .unwrap();
    }

    // Now setup watcher, to be able to query of signing identifier KEL.
    let (watcher_id, watcher_oobi) = ctx.watcher_data();

    // Resolve watcher oobi
    verifying_identifier
        .resolve_oobi(&Oobi::Location(watcher_oobi))
        .await?;

    // Generate and sign event, that will be sent to watcher, so it knows to act
    // as verifier's watcher.
    let add_watcher = verifying_identifier.add_watcher(IdentifierPrefix::Basic(watcher_id))?;
    let signature = SelfSigningPrefix::Ed25519Sha512(
        verifier_key_manager.sign(add_watcher.as_bytes()).unwrap(),
    );

    verifying_identifier
        .finalize_add_watcher(add_watcher.as_bytes(), signature)
        .await?;

    // Now query about signer's kel.
    // To find `signing_identifier`s KEL, `verifying_identifier` needs to
    // provide to watcher its oobi and oobi of its witnesses.
    for wit_oobi in vec![first_witness_oobi, second_witness_oobi] {
        let oobi = Oobi::Location(wit_oobi);
        verifying_identifier.resolve_oobi(&oobi).await?;
        verifying_identifier
            .send_oobi_to_watcher(&verifying_identifier.id(), &oobi)
            .await?;
    }
    let signer_oobi = EndRole {
        cid: signing_identifier.id().clone(),
        role: keri_core::oobi::Role::Witness,
        eid: keri_controller::IdentifierPrefix::Basic(second_witness_id.clone()),
    };

    verifying_identifier
        .send_oobi_to_watcher(&verifying_identifier.id(), &Oobi::EndRole(signer_oobi))
        .await?;

    // Query kel of signing identifier
    let signing_event_seal = signing_identifier.get_last_event_seal()?;
    let queries_and_signatures: Vec<_> = verifying_identifier
        .query_watchers(&signing_event_seal)?
        .into_iter()
        .map(|qry| {
            let signature = SelfSigningPrefix::Ed25519Sha512(
                verifier_key_manager.sign(&qry.encode().unwrap()).unwrap(),
            );
            (qry, signature)
        })
        .collect();

    let (mut response, mut errors) = verifying_identifier
        .finalize_query(queries_and_signatures.clone())
        .await;
    // Watcher might need some time to find KEL. Ask about it until it's ready.
    while !errors.is_empty() {
        sleep(Duration::from_millis(500)).await;
        (response, errors) = verifying_identifier
            .finalize_query(queries_and_signatures.clone())
            .await;
    }

    assert_eq!(response, QueryResponse::Updates);

    // No updates after querying again
    (response, _) = verifying_identifier
        .finalize_query(queries_and_signatures.clone())
        .await;
    assert_eq!(response, QueryResponse::NoUpdates);

    // Verify signed message.
    assert!(verifying_controller
        .verify(first_message, &first_signature)
        .is_ok());

    // Rotate signer keys
    key_manager.rotate()?;
    let pk = BasicPrefix::Ed25519(key_manager.public_key());
    let npk = BasicPrefix::Ed25519(key_manager.next_public_key());

    // Rotation needs two witness receipts to be accepted
    let rotation_event = signing_identifier
        .rotate(vec![pk], vec![npk], 1, vec![], vec![], 2)
        .await?;

    let signature = SelfSigningPrefix::Ed25519Sha512(key_manager.sign(rotation_event.as_bytes())?);
    signing_identifier
        .finalize_rotate(rotation_event.as_bytes(), signature)
        .await?;

    // Publish event to actor's witnesses
    signing_identifier.notify_witnesses().await.unwrap();

    // Querying witnesses to get receipts
    for qry in signing_identifier
        .query_mailbox(
            signing_identifier.id(),
            &[first_witness_id.clone(), second_witness_id.clone()],
        )
        .unwrap()
    {
        let signature =
            SelfSigningPrefix::Ed25519Sha512(key_manager.sign(&qry.encode().unwrap()).unwrap());
        signing_identifier
            .finalize_query_mailbox(vec![(qry, signature)])
            .await
            .unwrap();
    }

    // Sign message with rotated keys.
    let second_message = "Hi".as_bytes();
    let second_message_signature = vec![SelfSigningPrefix::Ed25519Sha512(
        key_manager.sign(second_message).unwrap(),
    )];

    let current_event_seal = signing_identifier.get_last_establishment_event_seal()?;
    let second_signature =
        signing_identifier.sign_data(second_message, &second_message_signature)?;

    // Try to verify it, it should fail, because verifier doesn't know signer's rotation event.
    assert!(matches!(
        verifying_controller
            .verify(second_message, &second_signature)
            .unwrap_err(),
        VerificationError::MoreInfo(MoreInfoError::EventNotFound(_))
    ));

    // Query kel of signing identifier
    let queries_and_signatures: Vec<_> = verifying_identifier
        .query_watchers(&current_event_seal)?
        .into_iter()
        .map(|qry| {
            let signature = SelfSigningPrefix::Ed25519Sha512(
                verifier_key_manager.sign(&qry.encode().unwrap()).unwrap(),
            );
            (qry, signature)
        })
        .collect();

    let (mut response, mut errors) = verifying_identifier
        .finalize_query(queries_and_signatures.clone())
        .await;

    // Watcher might need some time to find KEL. Ask about it until it's ready.
    while !errors.is_empty() {
        sleep(Duration::from_millis(500)).await;
        (response, errors) = verifying_identifier
            .finalize_query(queries_and_signatures.clone())
            .await;
    }

    assert_eq!(&response, &QueryResponse::Updates);

    // No updates after querying again
    (response, _) = verifying_identifier
        .finalize_query(queries_and_signatures.clone())
        .await;
    assert_eq!(&response, &QueryResponse::NoUpdates);

    let verification_result = verifying_controller.verify(second_message, &second_signature);
    assert!(verification_result.is_ok());

    Ok(())
}
