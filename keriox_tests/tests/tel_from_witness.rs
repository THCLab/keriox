use std::{sync::Arc, collections::HashMap};

use controller::{error::ControllerError, LocationScheme, IdentifierPrefix, Controller, config::ControllerConfig, CryptoBox, BasicPrefix, KeyManager, SelfSigningPrefix, identifier_controller::IdentifierController};
use keri::{transport::test::{TestActor, TestTransport}, event_message::signed_event_message::Message};
use keri_tests::transport::{TelTestTransport, TelTestActor, TestActorMap};
use tempfile::Builder;
use url::Host;
use witness::{WitnessListener, WitnessEscrowConfig};


#[async_std::test]
async fn test_tel_from_witness() -> Result<(), ControllerError> {
    use url::Url;
    let root0 = Builder::new().prefix("test-db0").tempdir().unwrap();
    let root = Builder::new().prefix("test-db").tempdir().unwrap();

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
		trans.insert((Host::Domain("witness1".to_string()), 80), Arc::new(TelTestActor::Witness(witness1.witness_data.clone()))).await;
		trans

	};
    // let wit1_location: LocationScheme = serde_json::from_str(r#"{"eid":"BJq7UABlttINuWJh1Xl2lkqZG4NTdUdqnbFJDa6ZyxCC","scheme":"http","url":"http://localhost:3232/"}"#).unwrap();
    // let wit1_id: BasicPrefix = "BJq7UABlttINuWJh1Xl2lkqZG4NTdUdqnbFJDa6ZyxCC".parse().unwrap();
    let controller0 = Arc::new(Controller::new(ControllerConfig {
        db_path: root0.path().to_owned(),
        transport: Box::new(transport.clone()),
		tel_transport: Box::new(tel_transport.clone()),
        ..Default::default()
    })?);

    let controller = Arc::new(Controller::new(ControllerConfig {
        db_path: root.path().to_owned(),
        transport: Box::new(transport.clone()),
		tel_transport: Box::new(tel_transport),
        ..Default::default()
    })?);
    let km0 = CryptoBox::new()?;

    let mut verifier = {
        let pk = BasicPrefix::Ed25519(km0.public_key());
        let npk = BasicPrefix::Ed25519(km0.next_public_key());

        let icp_event = controller0
            .incept(
                vec![pk],
                vec![npk],
                vec![wit1_location.clone()],
                1,
            )
            .await?;
        let signature = SelfSigningPrefix::Ed25519Sha512(km0.sign(icp_event.as_bytes())?);

        let incepted_identifier = controller0
            .finalize_inception(icp_event.as_bytes(), &signature)
            .await?;
        IdentifierController::new(incepted_identifier, controller0.clone())
    };

    assert_eq!(verifier.notify_witnesses().await?, 1);

    // Querying mailbox to get receipts
    for qry in verifier.query_mailbox(&verifier.id, &[wit1_id.clone()])? {
        let signature = SelfSigningPrefix::Ed25519Sha512(km0.sign(&qry.encode()?)?);
        let act = verifier.finalize_query(vec![(qry, signature)]).await?;
        assert_eq!(act.len(), 0);
    }

    // assert!(matches!(
    //     witness1.witness_data.event_storage.get_kel_messages_with_receipts(&ident_ctl.id)?.unwrap().as_slice(),
    //     [Notice::Event(evt), Notice::NontransferableRct(rct)]
    //     if matches!(evt.event_message.data.event_data, EventData::Icp(_))
    //         && matches!(rct.signatures.len(), 1)
    // ));

    let state = verifier.source.get_state(&verifier.id)?;
    assert_eq!(state.sn, 0);


    let km1 = CryptoBox::new()?;

    let mut ident_ctl = {
        let pk = BasicPrefix::Ed25519(km1.public_key());
        let npk = BasicPrefix::Ed25519(km1.next_public_key());

        let icp_event = controller
            .incept(
                vec![pk],
                vec![npk],
                vec![wit1_location.clone()],
                1,
            )
            .await?;
        let signature = SelfSigningPrefix::Ed25519Sha512(km1.sign(icp_event.as_bytes())?);

        let incepted_identifier = controller
            .finalize_inception(icp_event.as_bytes(), &signature)
            .await?;
        IdentifierController::new(incepted_identifier, controller.clone())
    };

    assert_eq!(ident_ctl.notify_witnesses().await?, 1);

    // Querying mailbox to get receipts
    for qry in ident_ctl.query_mailbox(&ident_ctl.id, &[wit1_id.clone()])? {
        let signature = SelfSigningPrefix::Ed25519Sha512(km1.sign(&qry.encode()?)?);
        let act = ident_ctl.finalize_query(vec![(qry, signature)]).await?;
        assert_eq!(act.len(), 0);
    }

    // assert!(matches!(
    //     witness1.witness_data.event_storage.get_kel_messages_with_receipts(&ident_ctl.id)?.unwrap().as_slice(),
    //     [Notice::Event(evt), Notice::NontransferableRct(rct)]
    //     if matches!(evt.event_message.data.event_data, EventData::Icp(_))
    //         && matches!(rct.signatures.len(), 1)
    // ));

    let state = ident_ctl.source.get_state(&ident_ctl.id)?;
    assert_eq!(state.sn, 0);


    let msg_to_issue = "hello world";
    let vcp_ixn = ident_ctl.incept_registry()?;

    let signature = SelfSigningPrefix::Ed25519Sha512(km1.sign(&vcp_ixn)?);
    ident_ctl.finalize_event(&vcp_ixn, signature).await?;
    ident_ctl.notify_witnesses().await?;

    // Querying mailbox to get receipts
    for qry in ident_ctl.query_mailbox(&ident_ctl.id, &[wit1_id.clone()])? {
        let signature = SelfSigningPrefix::Ed25519Sha512(km1.sign(&qry.encode()?)?);
        let act = ident_ctl.finalize_query(vec![(qry, signature)]).await?;
        assert_eq!(act.len(), 0);
    }

    let state = ident_ctl.source.get_state(&ident_ctl.id)?;
    assert_eq!(state.sn, 1);

    let (vc_hash, iss_ixn) = ident_ctl.issue(msg_to_issue)?;

    let signature = SelfSigningPrefix::Ed25519Sha512(km1.sign(&iss_ixn)?);
    ident_ctl.finalize_event(&iss_ixn, signature).await?;
    ident_ctl.notify_witnesses().await?;

     // Querying mailbox to get receipts
    for qry in ident_ctl.query_mailbox(&ident_ctl.id, &[wit1_id.clone()])? {
        let signature = SelfSigningPrefix::Ed25519Sha512(km1.sign(&qry.encode()?)?);
        let act = ident_ctl.finalize_query(vec![(qry, signature)]).await?;
        assert_eq!(act.len(), 0);
    }


    let state = ident_ctl.source.get_state(&ident_ctl.id)?;
    assert_eq!(state.sn, 2);
    ident_ctl.notify_backers().await.unwrap();

    let qry = verifier.query_tel(ident_ctl.registry_id.as_ref().unwrap().clone(), vc_hash.clone())?;
    let signature = SelfSigningPrefix::Ed25519Sha512(km0.sign(&qry.encode().unwrap())?);
    verifier.finalize_tel_query(qry, signature).await?; // finalize_event(&iss_ixn, signature).await?;

    // verifier need to have issuer kel to accept tel events.
    // It can be obtained by query message, but we just simulate this.
    let kel = ident_ctl.source.storage.get_kel_messages_with_receipts(&ident_ctl.id)
        .unwrap()
        .unwrap()
        .into_iter()
        .map(|ev| Message::Notice(ev.clone())
        .to_cesr().unwrap()).flatten();

    // println!("kel: {}", kel);
    controller0.process_stream(&kel.collect::<Vec<_>>())?;


    if let IdentifierPrefix::SelfAddressing(sai) = &vc_hash {
        println!("\n\nhash: {}", sai.to_string());
        dbg!(controller0.tel.get_tel(&sai).unwrap());
    };


    // let incepted_identifier = controller
    //     .finalize_inception(icp_event.as_bytes(), &signature)
    //     .await?;

    Ok(())
}
