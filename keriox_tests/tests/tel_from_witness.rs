use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::Arc,
};

use controller::{
    config::ControllerConfig, error::ControllerError, identifier_controller::IdentifierController,
    BasicPrefix, Controller, CryptoBox, IdentifierPrefix, KeyManager, LocationScheme,
    SelfSigningPrefix,
};
use keri::{
    actor::error::ActorError, event_message::signed_event_message::Message,
    transport::test::TestTransport,
};
use keri_tests::transport::{TelTestActor, TelTestTransport};
use teliox::state::vc_state::TelState;
use tempfile::Builder;
use url::Host;
use witness::{WitnessEscrowConfig, WitnessListener};

async fn setup_identifier(
    root_path: &Path,
    witness_locations: Vec<LocationScheme>,
    transport: TestTransport<ActorError>,
    tel_transport: TelTestTransport,
) -> (IdentifierController, CryptoBox) {
    let verifier_controller = Arc::new(
        Controller::new(ControllerConfig {
            db_path: root_path.to_owned(),
            transport: Box::new(transport.clone()),
            tel_transport: Box::new(tel_transport.clone()),
            ..Default::default()
        })
        .unwrap(),
    );
    let witnesses_id: Vec<BasicPrefix> = witness_locations
        .iter()
        .map(|loc| match &loc.eid {
            IdentifierPrefix::Basic(bp) => bp.clone(),
            _ => unreachable!(),
        })
        .collect();

    let verifier_keypair = CryptoBox::new().unwrap();

    let mut verifier = {
        let pk = BasicPrefix::Ed25519(verifier_keypair.public_key());
        let npk = BasicPrefix::Ed25519(verifier_keypair.next_public_key());

        let icp_event = verifier_controller
            .incept(vec![pk], vec![npk], witness_locations, 1)
            .await
            .unwrap();
        let signature =
            SelfSigningPrefix::Ed25519Sha512(verifier_keypair.sign(icp_event.as_bytes()).unwrap());

        let incepted_identifier = verifier_controller
            .finalize_inception(icp_event.as_bytes(), &signature)
            .await
            .unwrap();
        IdentifierController::new(incepted_identifier, verifier_controller.clone())
    };

    assert_eq!(verifier.notify_witnesses().await.unwrap(), 1);

    // Querying mailbox to get receipts
    for qry in verifier.query_mailbox(&verifier.id, &witnesses_id).unwrap() {
        let signature = SelfSigningPrefix::Ed25519Sha512(
            verifier_keypair.sign(&qry.encode().unwrap()).unwrap(),
        );
        let act = verifier
            .finalize_query(vec![(qry, signature)])
            .await
            .unwrap();
        assert_eq!(act.len(), 0);
    }
    (verifier, verifier_keypair)
}

#[async_std::test]
async fn test_tel_from_witness() -> Result<(), ControllerError> {
    use url::Url;
    let root0 = Builder::new().prefix("test-db0").tempdir().unwrap();
    let root = Builder::new().prefix("test-db").tempdir().unwrap();

    // Setup witness
    let witness1 = {
        let seed = "AK8F6AAiYDpXlWdj2O5F5-6wNCCNJh2A4XOlqwR_HwwH";
        let witness_root = Builder::new().prefix("test-wit1-db").tempdir().unwrap();
        Arc::new(WitnessListener::setup(
            url::Url::parse("http://witness1/").unwrap(),
            witness_root.path(),
            Some(seed.to_string()),
            WitnessEscrowConfig::default(),
        )?)
    };

    let wit1_id = witness1.get_prefix();
    let wit1_location = LocationScheme {
        eid: IdentifierPrefix::Basic(wit1_id.clone()),
        scheme: keri::oobi::Scheme::Http,
        url: Url::parse("http://witness1/").unwrap(),
    };

    let transport = {
        let mut actors: keri::transport::test::TestActorMap = HashMap::new();
        actors.insert((Host::Domain("witness1".to_string()), 80), witness1.clone());
        TestTransport::new(actors)
    };
    let tel_transport = {
        let trans = TelTestTransport::new();
        trans
            .insert(
                (Host::Domain("witness1".to_string()), 80),
                TelTestActor::Witness(witness1.witness_data.clone()),
            )
            .await;
        trans
    };

    // Setup verifier identifier
    let (verifier, verifier_keypair) = setup_identifier(
        root0.path(),
        vec![wit1_location.clone()],
        transport.clone(),
        tel_transport.clone(),
    )
    .await;

    let state = verifier.source.get_state(&verifier.id)?;
    assert_eq!(state.sn, 0);

    let (mut issuer, issuer_keypair) =
        setup_identifier(root.path(), vec![wit1_location], transport, tel_transport).await;

    let state = issuer.source.get_state(&issuer.id)?;
    assert_eq!(state.sn, 0);

    // Issue message.
    let msg_to_issue = "hello world";
    // Incept registry. It'll generate ixn that need to be signed.
    let vcp_ixn = issuer.incept_registry()?;

    let signature = SelfSigningPrefix::Ed25519Sha512(issuer_keypair.sign(&vcp_ixn)?);
    issuer.finalize_event(&vcp_ixn, signature).await?;
    issuer.notify_witnesses().await?;

    // Querying mailbox to get receipts
    for qry in issuer.query_mailbox(&issuer.id, &[wit1_id.clone()])? {
        let signature = SelfSigningPrefix::Ed25519Sha512(issuer_keypair.sign(&qry.encode()?)?);
        let act = issuer.finalize_query(vec![(qry, signature)]).await?;
        assert_eq!(act.len(), 0);
    }

    let state = issuer.source.get_state(&issuer.id)?;
    assert_eq!(state.sn, 1);

    // Issue message. It'll generate ixn message, that need to be signed.
    let (vc_hash, iss_ixn) = issuer.issue(msg_to_issue)?;
    let sai = match &vc_hash {
        IdentifierPrefix::SelfAddressing(sai) => sai.clone(),
        _ => unreachable!(),
    };

    let signature = SelfSigningPrefix::Ed25519Sha512(issuer_keypair.sign(&iss_ixn)?);
    issuer.finalize_event(&iss_ixn, signature).await?;
    issuer.notify_witnesses().await?;

    // Querying mailbox to get receipts
    for qry in issuer.query_mailbox(&issuer.id, &[wit1_id.clone()])? {
        let signature = SelfSigningPrefix::Ed25519Sha512(issuer_keypair.sign(&qry.encode()?)?);
        let act = issuer.finalize_query(vec![(qry, signature)]).await?;
        assert_eq!(act.len(), 0);
    }

    // Provided ixns are accepted in issuer's kel.
    let state = issuer.source.get_state(&issuer.id)?;
    assert_eq!(state.sn, 2);
    // Tel events are accepted in
    let vc_state = issuer.source.tel.get_vc_state(&sai).unwrap();
    assert!(matches!(vc_state, Some(TelState::Issued(_))));
    // Now publish corresponding tel events to backers. Verifier can find them there.
    issuer.notify_backers().await.unwrap();

    // Query witness about issuer's tel.
    let qry = verifier.query_tel(
        issuer.registry_id.as_ref().unwrap().clone(),
        vc_hash.clone(),
    )?;
    let signature =
        SelfSigningPrefix::Ed25519Sha512(verifier_keypair.sign(&qry.encode().unwrap())?);
    verifier.finalize_tel_query(qry, signature).await?;

    let vc_state = verifier.source.tel.get_vc_state(&sai).unwrap();
    assert!(matches!(vc_state, None));

    // verifier need to have issuer kel to accept tel events.
    // It can be obtained by query message, but we just simulate this.
    let kel = issuer
        .source
        .storage
        .get_kel_messages_with_receipts(&issuer.id)
        .unwrap()
        .unwrap()
        .into_iter()
        .map(|ev| Message::Notice(ev.clone()).to_cesr().unwrap())
        .flatten();

    verifier.source.process_stream(&kel.collect::<Vec<_>>())?;

    let vc_state = verifier.source.tel.get_vc_state(&sai).unwrap();
    assert!(matches!(vc_state, Some(TelState::Issued(_))));

    // Revoke issued message
    let rev_ixn = issuer.revoke(&sai)?;
    let sai = match &vc_hash {
        IdentifierPrefix::SelfAddressing(sai) => sai.clone(),
        _ => unreachable!(),
    };

    let signature = SelfSigningPrefix::Ed25519Sha512(issuer_keypair.sign(&rev_ixn)?);
    issuer.finalize_event(&rev_ixn, signature).await?;
    issuer.notify_witnesses().await?;

    // Querying mailbox to get receipts
    for qry in issuer.query_mailbox(&issuer.id, &[wit1_id.clone()])? {
        let signature = SelfSigningPrefix::Ed25519Sha512(issuer_keypair.sign(&qry.encode()?)?);
        let act = issuer.finalize_query(vec![(qry, signature)]).await?;
        assert_eq!(act.len(), 0);
    }

    // Provided ixns are accepted in issuer's kel.
    let state = issuer.source.get_state(&issuer.id)?;
    assert_eq!(state.sn, 3);
    // Tel events are accepted in
    let vc_state = issuer.source.tel.get_vc_state(&sai).unwrap();
    assert!(matches!(vc_state, Some(TelState::Revoked)));
    // Now publish corresponding tel events to backers. Verifier can find them there.
    issuer.notify_backers().await.unwrap();

    // Check vc state with verifier identifier
    // Query witness about issuer's tel again.
    let qry = verifier.query_tel(
        issuer.registry_id.as_ref().unwrap().clone(),
        vc_hash.clone(),
    )?;
    let signature =
        SelfSigningPrefix::Ed25519Sha512(verifier_keypair.sign(&qry.encode().unwrap())?);
    verifier.finalize_tel_query(qry, signature).await?;

    // verifier need to update issuer's kel to accept tel events.
    let kel = issuer
        .source
        .storage
        .get_kel_messages_with_receipts(&issuer.id)
        .unwrap()
        .unwrap()
        .into_iter()
        .map(|ev| Message::Notice(ev.clone()).to_cesr().unwrap())
        .flatten();

    verifier.source.process_stream(&kel.collect::<Vec<_>>())?;

    let vc_state = verifier.source.tel.get_vc_state(&sai).unwrap();
    assert!(matches!(vc_state, Some(TelState::Revoked)));

    Ok(())
}
