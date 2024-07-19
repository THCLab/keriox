use std::time::Duration;
use std::{collections::HashMap, sync::Arc};

use async_std::task::sleep;
use keri_controller::{
    error::ControllerError, IdentifierPrefix, KeyManager, LocationScheme, SelfSigningPrefix,
};
use keri_controller::{EndRole, Oobi};
use keri_core::actor::prelude::{HashFunction, HashFunctionCode};
use keri_core::transport::test::TestTransport;
use keri_tests::{
    setup_identifier,
    transport::{TelTestActor, TelTestTransport},
};
use teliox::state::vc_state::TelState;
use tempfile::Builder;
use url::{Host, Url};
use watcher::{WatcherConfig, WatcherListener};
use witness::{WitnessEscrowConfig, WitnessListener};

#[async_std::test]
async fn test_tel_from_watcher() -> Result<(), ControllerError> {
    let verifier_db_path = Builder::new().prefix("test-db0").tempdir().unwrap();
    let issuer_db_path = Builder::new().prefix("test-db").tempdir().unwrap();

    // Setup test witness
    let verifier_witness_url = url::Url::parse("http://witness1/").unwrap();
    let verifier_witness = {
        let seed = "AK8F6AAiYDpXlWdj2O5F5-6wNCCNJh2A4XOlqwR_HwwH";
        let witness_db_path = Builder::new().prefix("test-wit1-db").tempdir().unwrap();
        Arc::new(
            WitnessListener::setup(
                verifier_witness_url.clone(),
                witness_db_path.path(),
                Some(seed.to_string()),
                WitnessEscrowConfig::default(),
            )
            .unwrap(),
        )
    };

    let verifier_witness_id = verifier_witness.get_prefix();
    let verifier_witness_location = LocationScheme {
        eid: IdentifierPrefix::Basic(verifier_witness_id.clone()),
        scheme: keri_core::oobi::Scheme::Http,
        url: verifier_witness_url,
    };

    // Setup second test witness
    let issuer_witness_url = url::Url::parse("http://witness2/").unwrap();
    let issuer_witness = {
        let seed = "AK8F6AAiYDpXlWdj2O5F5-6wNCCNJh2A4XOlqwR_Hwwg";
        let witness_db_path = Builder::new().prefix("test-wit2-db").tempdir().unwrap();
        Arc::new(
            WitnessListener::setup(
                issuer_witness_url.clone(),
                witness_db_path.path(),
                Some(seed.to_string()),
                WitnessEscrowConfig::default(),
            )
            .unwrap(),
        )
    };

    let issuer_witness_id = issuer_witness.get_prefix();
    let issuer_witness_location = LocationScheme {
        eid: IdentifierPrefix::Basic(issuer_witness_id.clone()),
        scheme: keri_core::oobi::Scheme::Http,
        url: issuer_witness_url,
    };

    // Setup test watcher
    let watcher = {
        let watcher_transport = {
            let mut actors: keri_core::transport::test::TestActorMap = HashMap::new();
            actors.insert(
                (Host::Domain("witness1".to_string()), 80),
                verifier_witness.clone(),
            );
            actors.insert(
                (Host::Domain("witness2".to_string()), 80),
                issuer_witness.clone(),
            );
            TestTransport::new(actors)
        };

        let trans = TelTestTransport::new();
        trans
            .insert(
                (Host::Domain("witness1".to_string()), 80),
                TelTestActor::Witness(verifier_witness.witness_data.clone()),
            )
            .await;
        trans
            .insert(
                (Host::Domain("witness2".to_string()), 80),
                TelTestActor::Witness(issuer_witness.witness_data.clone()),
            )
            .await;

        let watcher_db_path = Builder::new().prefix("cont-test-db").tempdir().unwrap();
        let watcher_listener = Arc::new(WatcherListener::new(WatcherConfig {
            public_address: Url::parse("http://watcher1/").unwrap(),
            db_path: watcher_db_path.path().to_owned(),
            transport: Box::new(watcher_transport),
            tel_transport: Box::new(trans),
            ..Default::default()
        })?);
        async_std::task::spawn(watcher::watcher_listener::update_checking(
            watcher_listener.watcher.clone(),
        ));
        watcher_listener
    };

    let watcher_identifier = watcher.clone().get_prefix();
    let watcher_location = LocationScheme {
        eid: IdentifierPrefix::Basic(watcher_identifier.clone()),
        scheme: keri_core::oobi::Scheme::Http,
        url: Url::parse("http://watcher1/").unwrap(),
    };

    // Setup test transports, that will be used by controllers to communicate
    // with watcher and witness.
    let transport = {
        let mut actors: keri_core::transport::test::TestActorMap = HashMap::new();
        actors.insert(
            (Host::Domain("witness1".to_string()), 80),
            verifier_witness.clone(),
        );
        actors.insert(
            (Host::Domain("witness2".to_string()), 80),
            issuer_witness.clone(),
        );
        actors.insert((Host::Domain("watcher1".to_string()), 80), watcher.clone());
        TestTransport::new(actors)
    };

    let tel_transport = {
        let trans = TelTestTransport::new();
        trans
            .insert(
                (Host::Domain("witness1".to_string()), 80),
                TelTestActor::Witness(verifier_witness.witness_data.clone()),
            )
            .await;
        trans
            .insert(
                (Host::Domain("witness2".to_string()), 80),
                TelTestActor::Witness(issuer_witness.witness_data.clone()),
            )
            .await;
        trans
            .insert(
                (Host::Domain("watcher1".to_string()), 80),
                TelTestActor::Watcher(watcher.watcher.clone()),
            )
            .await;
        trans
    };

    // Setup verifier identifier
    let (mut verifier, verifier_keypair, verifier_controller) = setup_identifier(
        verifier_db_path.path(),
        vec![verifier_witness_location.clone()],
        Some(transport.clone()),
        Some(tel_transport.clone()),
    )
    .await;

    let state = verifier.find_state(verifier.id())?;
    assert_eq!(state.sn, 0);

    // Setup verifier's watcher
    verifier
        .resolve_oobi(&Oobi::Location(watcher_location))
        .await?;
    let add_watcher = verifier.add_watcher(IdentifierPrefix::Basic(watcher_identifier))?;
    let signature =
        SelfSigningPrefix::Ed25519Sha512(verifier_keypair.sign(add_watcher.as_bytes()).unwrap());

    verifier
        .finalize_add_watcher(add_watcher.as_bytes(), signature)
        .await?;

    // Setup issuer identifier
    let (mut issuer, issuer_keypair, _issuer_controller) = setup_identifier(
        issuer_db_path.path(),
        vec![issuer_witness_location.clone()],
        Some(transport),
        Some(tel_transport.clone()),
    )
    .await;

    let state = issuer.find_state(issuer.id())?;
    assert_eq!(state.sn, 0);

    // Issue message.
    let msg_to_issue = "hello world";
    let credential_said =
        HashFunction::from(HashFunctionCode::Blake3_256).derive(msg_to_issue.as_bytes());
    // Incept registry. It'll generate ixn that need to be signed.
    let (_vcp_id, vcp_ixn) = issuer.incept_registry()?;

    let signature = SelfSigningPrefix::Ed25519Sha512(issuer_keypair.sign(&vcp_ixn)?);
    issuer.finalize_incept_registry(&vcp_ixn, signature).await?;

    issuer.notify_witnesses().await?;

    // Querying mailbox to get receipts
    for qry in issuer.query_mailbox(issuer.id(), &[issuer_witness_id.clone()])? {
        let signature = SelfSigningPrefix::Ed25519Sha512(issuer_keypair.sign(&qry.encode()?)?);
        let _act = issuer
            .finalize_query_mailbox(vec![(qry, signature)])
            .await?;
    }

    let state = issuer.find_state(issuer.id())?;
    assert_eq!(state.sn, 1);

    // Issue message. It'll generate ixn message, that need to be signed.
    let (vc_hash, iss_ixn) = issuer.issue(credential_said)?;
    let sai = match &vc_hash {
        IdentifierPrefix::SelfAddressing(sai) => sai.clone(),
        _ => unreachable!(),
    };

    let signature = SelfSigningPrefix::Ed25519Sha512(issuer_keypair.sign(&iss_ixn)?);
    issuer.finalize_issue(&iss_ixn, signature).await?;
    issuer.notify_witnesses().await?;

    // Querying mailbox to get receipts
    for qry in issuer.query_mailbox(issuer.id(), &[issuer_witness_id.clone()])? {
        let signature = SelfSigningPrefix::Ed25519Sha512(issuer_keypair.sign(&qry.encode()?)?);
        let _act = issuer
            .finalize_query_mailbox(vec![(qry, signature)])
            .await?;
    }

    // Provided ixns are accepted in issuer's kel.
    let state = issuer.find_state(issuer.id())?;
    assert_eq!(state.sn, 2);
    // Tel events are accepted
    let vc_state = issuer.find_vc_state(&sai).unwrap();
    assert!(matches!(vc_state, Some(TelState::Issued(_))));
    // Now publish corresponding tel events to backers. Verifier can find them there.
    issuer.notify_backers().await.unwrap();

    // verifier needs to have issuer's KEL to accept TEL events. Query it's
    // watcher for it.
    // `last_event_seal`, `registry_id` and `vc_hash` should be provided to
    // verifier by issuer.
    let last_event_seal = issuer.get_last_event_seal()?;
    let registry_id = issuer.registry_id().unwrap().clone();

    // To find `signing_identifier`s KEL, verifying_identifier` needs to
    // provide to watcher its oobi and oobi of its witnesses.
    for wit_oobi in vec![issuer_witness_location] {
        let oobi = Oobi::Location(wit_oobi);
        // verifier.resolve_oobi(&oobi).await?;
        verifier.send_oobi_to_watcher(&verifier.id(), &oobi).await?;
    }
    let signer_oobi = EndRole {
        cid: issuer.id().clone(),
        role: keri_core::oobi::Role::Witness,
        eid: keri_controller::IdentifierPrefix::Basic(issuer_witness_id.clone()),
    };

    verifier
        .send_oobi_to_watcher(&verifier.id(), &Oobi::EndRole(signer_oobi))
        .await?;

    // Query kel of signing identifier
    let queries_and_signatures: Vec<_> = verifier
        .query_watchers(&last_event_seal)?
        .into_iter()
        .map(|qry| {
            let signature = SelfSigningPrefix::Ed25519Sha512(
                verifier_keypair.sign(&qry.encode().unwrap()).unwrap(),
            );
            (qry, signature)
        })
        .collect();

    verifier
        .finalize_query(queries_and_signatures.clone())
        .await;

    let issuers_state_in_verifier = verifier_controller.find_state(issuer.id()).unwrap();
    assert_eq!(issuers_state_in_verifier.sn, 2);

    // To find issuer`s TEL, verifier needs to provide to watcher its oobi
    println!("\n\nRegistry id: {}", registry_id);

    let signer_tel_oobi = EndRole {
        cid: registry_id.clone(),
        role: keri_core::oobi::Role::Witness,
        eid: keri_controller::IdentifierPrefix::Basic(issuer_witness_id.clone()),
    };

    verifier
        .send_oobi_to_watcher(&verifier.id(), &Oobi::EndRole(signer_tel_oobi))
        .await?;

    // Query witness about issuer's TEL.
    let qry = verifier.query_tel(registry_id.clone(), vc_hash.clone())?;
    let signature =
        SelfSigningPrefix::Ed25519Sha512(verifier_keypair.sign(&qry.encode().unwrap())?);
    verifier
        .finalize_query_tel(issuer.id(), qry, signature)
        .await?;

    // Give watcher a moment to find TEL and ask again
    sleep(Duration::from_secs(1)).await;

    // Query witness about issuer's TEL.
    let qry = verifier.query_tel(registry_id, vc_hash.clone())?;
    let signature =
        SelfSigningPrefix::Ed25519Sha512(verifier_keypair.sign(&qry.encode().unwrap())?);
    verifier
        .finalize_query_tel(issuer.id(), qry, signature)
        .await?;

    let vc_state = verifier.find_vc_state(&sai).unwrap();
    assert!(matches!(vc_state, Some(TelState::Issued(_))));

    // Revoke issued message
    let rev_ixn = issuer.revoke(&sai)?;
    let sai = match &vc_hash {
        IdentifierPrefix::SelfAddressing(sai) => sai.clone(),
        _ => unreachable!(),
    };

    let signature = SelfSigningPrefix::Ed25519Sha512(issuer_keypair.sign(&rev_ixn)?);
    issuer.finalize_revoke(&rev_ixn, signature).await?;
    issuer.notify_witnesses().await?;

    // Querying mailbox to get receipts
    for qry in issuer.query_mailbox(issuer.id(), &[issuer_witness_id.clone()])? {
        let signature = SelfSigningPrefix::Ed25519Sha512(issuer_keypair.sign(&qry.encode()?)?);
        let _act = issuer
            .finalize_query_mailbox(vec![(qry, signature)])
            .await?;
    }

    // Provided ixns are accepted in issuer's kel.
    let state = issuer.find_state(issuer.id())?;
    assert_eq!(state.sn, 3);
    // Tel events are accepted in
    let vc_state = issuer.find_vc_state(&sai).unwrap();
    assert!(matches!(vc_state, Some(TelState::Revoked)));
    // Now publish corresponding tel events to backers. Verifier can find them there.
    issuer.notify_backers().await.unwrap();

    // Query watcher for updates in issuer's KEL
    let last_event_seal = issuer.get_last_event_seal()?;
    let queries_and_signatures: Vec<_> = verifier
        .query_watchers(&last_event_seal)?
        .into_iter()
        .map(|qry| {
            let signature = SelfSigningPrefix::Ed25519Sha512(
                verifier_keypair.sign(&qry.encode().unwrap()).unwrap(),
            );
            (qry, signature)
        })
        .collect();

    let (_updates, mut errs) = verifier
        .finalize_query(queries_and_signatures.clone())
        .await;

    // Watcher may need some time to find KEL. Query it multiple times.
    while !errs.is_empty() {
        (_, errs) = verifier
            .finalize_query(queries_and_signatures.clone())
            .await;
    }

    // Query witness about issuer's tel again.
    let registry_id = issuer.registry_id().unwrap().clone();
    let qry = verifier.query_tel(registry_id.clone(), vc_hash.clone())?;
    let signature =
        SelfSigningPrefix::Ed25519Sha512(verifier_keypair.sign(&qry.encode().unwrap())?);
    verifier
        .finalize_query_tel(issuer.id(), qry, signature)
        .await?;

    // Give watcher a moment to find TEL and ask again
    sleep(Duration::from_secs(1)).await;

    let qry = verifier.query_tel(registry_id, vc_hash.clone())?;
    let signature =
        SelfSigningPrefix::Ed25519Sha512(verifier_keypair.sign(&qry.encode().unwrap())?);
    verifier
        .finalize_query_tel(issuer.id(), qry, signature)
        .await?;

    let vc_state = verifier.find_vc_state(&sai).unwrap();
    assert!(matches!(vc_state, Some(TelState::Revoked)));

    Ok(())
}
