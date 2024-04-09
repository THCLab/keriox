use std::{collections::HashMap, net::Ipv4Addr, sync::Arc};

use anyhow::Result;
use keri_controller::{
    config::ControllerConfig, controller::Controller, error::ControllerError,
    mailbox_updating::ActionRequired, Oobi,
};
use keri_core::{
    oobi::{EndRole, LocationScheme, Role},
    prefix::{BasicPrefix, IdentifierPrefix, SelfSigningPrefix},
    signer::{CryptoBox, KeyManager},
    transport::test::{TestActorMap, TestTransport},
};
use tempfile::Builder;
use url::{Host, Url};
use watcher::{WatcherConfig, WatcherListener};
use witness::{WitnessEscrowConfig, WitnessListener};

#[async_std::test]
async fn test_multisig() -> Result<()> {
    let wit = {
        let wit_root = Builder::new().prefix("wit-db").tempdir().unwrap();
        Arc::new(
            WitnessListener::setup(
                Url::parse("http://127.0.0.1:3232").unwrap(),
                wit_root.path(),
                Some("ArwXoACJgOleVZ2PY7kXn7rA0II0mHYDhc6WrBH8fDAc".to_string()),
                WitnessEscrowConfig::default(),
            )
            .unwrap(),
        )
    };
    let witness_id = wit.get_prefix();
    let witness_oobi = LocationScheme {
        eid: IdentifierPrefix::Basic(witness_id.clone()),
        scheme: keri_core::oobi::Scheme::Http,
        url: Url::parse("http://127.0.0.1:3232").unwrap(),
    };

    let mut actors: TestActorMap = HashMap::new();
    actors.insert((Host::Ipv4(Ipv4Addr::LOCALHOST), 3232), wit.clone());
    let transport = Box::new(TestTransport::new(actors));

    let watcher_url = Url::parse("http://127.0.0.1:3236").unwrap();
    let watcher_listener = {
        let root = Builder::new().prefix("cont-test-db").tempdir().unwrap();
        WatcherListener::new(WatcherConfig {
            public_address: watcher_url.clone(),
            db_path: root.path().to_owned(),
            transport,
            ..Default::default()
        })?
    };
    let watcher = watcher_listener.watcher_data.clone();
    let watcher_id = watcher.0.prefix.clone();
    let watcher_oobi = LocationScheme {
        eid: IdentifierPrefix::Basic(watcher_id.clone()),
        scheme: keri_core::oobi::Scheme::Http,
        url: watcher_url.clone(),
    };

    let mut actors: TestActorMap = HashMap::new();
    actors.insert((Host::Ipv4(Ipv4Addr::LOCALHOST), 3232), wit);
    actors.insert(
        (Host::Ipv4(Ipv4Addr::LOCALHOST), 3236),
        Arc::new(watcher_listener),
    );
    let transport = Box::new(TestTransport::new(actors));

    // Setup first identifier.
    let root = Builder::new().prefix("test-db").tempdir().unwrap();
    let controller1 = Arc::new(
        Controller::new(ControllerConfig {
            db_path: root.path().to_owned(),
            transport: transport.clone(),
            ..Default::default()
        })
        .unwrap(),
    );

    let km1 = CryptoBox::new()?;
    let pk = BasicPrefix::Ed25519(km1.public_key());
    let npk = BasicPrefix::Ed25519(km1.next_public_key());

    let icp_event = controller1
        .incept(vec![pk], vec![npk], vec![witness_oobi.clone()], 1)
        .await
        .unwrap();
    let signature = SelfSigningPrefix::Ed25519Sha512(km1.sign(icp_event.as_bytes())?);

    let mut identifier1 = controller1
        .finalize_incept(icp_event.as_bytes(), &signature)
        .unwrap();

    identifier1.notify_witnesses().await?;
    // Quering mailbox to get receipts
    let query = identifier1.query_mailbox(identifier1.id(), &[witness_id.clone()])?;

    for qry in query {
        let signature = SelfSigningPrefix::Ed25519Sha512(km1.sign(&qry.encode()?)?);
        identifier1.finalize_query(vec![(qry, signature)]).await?;
    }
    assert!(identifier1.get_kel().is_some());

    // Setup second identifier.
    let root2 = Builder::new().prefix("test-db").tempdir().unwrap();
    let controller2 = Arc::new(
        Controller::new(ControllerConfig {
            db_path: root2.path().to_owned(),
            transport,
            ..Default::default()
        })
        .unwrap(),
    );
    let km2 = CryptoBox::new()?;

    let pk = BasicPrefix::Ed25519(km2.public_key());
    let npk = BasicPrefix::Ed25519(km2.next_public_key());

    let icp_event = controller2
        .incept(vec![pk], vec![npk], vec![witness_oobi.clone()], 1)
        .await
        .unwrap();
    let signature = SelfSigningPrefix::Ed25519Sha512(km2.sign(icp_event.as_bytes())?);

    let mut identifier2 = controller2
        .finalize_incept(icp_event.as_bytes(), &signature)
        .unwrap();
    identifier2.notify_witnesses().await?;

    // Quering mailbox to get receipts
    let query = identifier2.query_mailbox(identifier2.id(), &[witness_id.clone()])?;

    for qry in query {
        let signature = SelfSigningPrefix::Ed25519Sha512(km2.sign(&qry.encode()?)?);
        identifier2.finalize_query(vec![(qry, signature)]).await?;
    }
    assert!(identifier2.get_kel().is_some());

    // Identifier1 adds watcher
    identifier1
        .resolve_oobi(&Oobi::Location(watcher_oobi.clone()))
        .await?;

    let add_watcher = identifier1
        .add_watcher(IdentifierPrefix::Basic(watcher_id.clone()))
        .unwrap();

    println!("add_watcher: {}", add_watcher);
    let add_watcher_sig = SelfSigningPrefix::Ed25519Sha512(km1.sign(add_watcher.as_bytes())?);

    identifier1
        .finalize_event(add_watcher.as_bytes(), add_watcher_sig)
        .await?;
    assert_eq!(
        identifier1.watchers()?,
        vec![IdentifierPrefix::Basic(watcher_id)]
    );

    // Send identifier2 oobis to identifier1's watchers and query for results.
    assert_eq!(
        r#"{"eid":"BJq7UABlttINuWJh1Xl2lkqZG4NTdUdqnbFJDa6ZyxCC","scheme":"http","url":"http://127.0.0.1:3232/"}"#,
        &serde_json::to_string(&witness_oobi).unwrap()
    );
    let oobi2 = EndRole {
        cid: identifier2.id().clone(),
        role: Role::Witness,
        eid: IdentifierPrefix::Basic(witness_id.clone()),
    };

    identifier1
        .send_oobi_to_watcher(&identifier1.id(), &Oobi::Location(witness_oobi))
        .await?;
    identifier1
        .send_oobi_to_watcher(&identifier1.id(), &Oobi::EndRole(oobi2))
        .await?;

    let qry_watcher =
        identifier1.query_own_watchers(&identifier2.get_last_establishment_event_seal()?)?;
    for qry in qry_watcher {
        let signature = SelfSigningPrefix::Ed25519Sha512(km1.sign(&qry.encode()?)?);
        identifier1.finalize_query(vec![(qry, signature)]).await?;
    }

    // Incept group
    let (group_inception, exn_messages) = identifier1.incept_group(
        vec![identifier2.id().clone()],
        2,
        Some(vec![witness_id.clone()]),
        Some(1),
        None,
    )?;

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

    let kel = controller1.get_kel_with_receipts(&group_id);
    // Event is not yet accepted.
    assert!(kel.is_none());

    // Quering mailbox to get multisig request
    let query = identifier2.query_mailbox(&identifier2.id(), &[witness_id.clone()])?;

    for qry in query {
        let signature = SelfSigningPrefix::Ed25519Sha512(km2.sign(&qry.encode()?)?);
        let res = identifier2.finalize_query(vec![(qry, signature)]).await?;

        match &res[0] {
            ActionRequired::DelegationRequest(_, _) => {
                unreachable!()
            }
            ActionRequired::MultisigRequest(multisig_event, exn) => {
                let signature_ixn =
                    SelfSigningPrefix::Ed25519Sha512(km2.sign(&multisig_event.encode()?)?);
                let signature_exn = SelfSigningPrefix::Ed25519Sha512(km2.sign(&exn.encode()?)?);
                identifier2
                    .finalize_group_incept(
                        &multisig_event.encode()?,
                        signature_ixn.clone(),
                        vec![(exn.encode()?, signature_exn)],
                    )
                    .await?;
            }
        };
    }

    // Query to get events signed by other participants
    let query = identifier1.query_mailbox(&group_id, &[witness_id.clone()])?;

    for qry in query {
        let signature = SelfSigningPrefix::Ed25519Sha512(km1.sign(&qry.encode()?)?);
        identifier1.finalize_query(vec![(qry, signature)]).await?;
    }

    // Query to have receipt of group inception
    let query = identifier1.query_mailbox(&group_id, &[witness_id.clone()])?;

    for qry in query {
        let signature = SelfSigningPrefix::Ed25519Sha512(km1.sign(&qry.encode()?)?);
        identifier1.finalize_query(vec![(qry, signature)]).await?;
    }

    let group_state_1 = identifier1.find_state(&group_id)?;
    assert_eq!(group_state_1.sn, 0);

    let group_state_2 = identifier2.find_state(&group_id);
    assert!(matches!(
        group_state_2,
        Err(ControllerError::UnknownIdentifierError)
    ));

    // Query to have receipt of group inception
    let query = identifier2.query_mailbox(&group_id, &[witness_id.clone()])?;

    for qry in query {
        let signature = SelfSigningPrefix::Ed25519Sha512(km2.sign(&qry.encode()?)?);
        identifier2.finalize_query(vec![(qry, signature)]).await?;
    }

    let group_state_2 = identifier2.find_state(&group_id)?;
    assert_eq!(group_state_2.sn, 0);

    Ok(())
}
