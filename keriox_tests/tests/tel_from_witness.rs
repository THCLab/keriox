use std::{collections::HashMap, sync::Arc};

use controller::{
    error::ControllerError, IdentifierPrefix, KeyManager, LocationScheme, SelfSigningPrefix,
};
use keri::{event_message::signed_event_message::Message, transport::test::TestTransport};
use keri_tests::{
    setup_identifier,
    transport::{TelTestActor, TelTestTransport},
};
use said::derivation::{HashFunction, HashFunctionCode};
use teliox::state::vc_state::TelState;
use tempfile::Builder;
use url::Host;
use witness::{WitnessEscrowConfig, WitnessListener};

#[async_std::test]
async fn test_tel_from_witness() -> Result<(), ControllerError> {
    use url::Url;
    let root0 = Builder::new().prefix("test-db0").tempdir().unwrap();
    let root = Builder::new().prefix("test-db").tempdir().unwrap();

    // Setup witness
    let witness1 = {
        let seed = "AK8F6AAiYDpXlWdj2O5F5-6wNCCNJh2A4XOlqwR_HwwH";
        let witness_root = Builder::new().prefix("test-wit1-db").tempdir().unwrap();
        Arc::new(
            WitnessListener::setup(
                url::Url::parse("http://witness1/").unwrap(),
                witness_root.path(),
                Some(seed.to_string()),
                WitnessEscrowConfig::default(),
            )
            .unwrap(),
        )
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
    let credential_said =
        HashFunction::from(HashFunctionCode::Blake3_256).derive(msg_to_issue.as_bytes());
    // Incept registry. It'll generate ixn that need to be signed.
    let (_vcp_id, vcp_ixn) = issuer.incept_registry()?;

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
    let (vc_hash, iss_ixn) = issuer.issue(credential_said)?;
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

    let signature =
        SelfSigningPrefix::Ed25519Sha512(verifier_keypair.sign(&qry.encode().unwrap())?);
    verifier
        .finalize_tel_query(&issuer.id, qry, signature)
        .await?;

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

    let signature =
        SelfSigningPrefix::Ed25519Sha512(verifier_keypair.sign(&qry.encode().unwrap())?);
    verifier
        .finalize_tel_query(&issuer.id, qry, signature)
        .await?;

    let vc_state = verifier.source.tel.get_vc_state(&sai).unwrap();
    assert!(matches!(vc_state, Some(TelState::Revoked)));

    Ok(())
}
