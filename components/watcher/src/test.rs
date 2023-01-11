#![cfg(test)]

use std::{
    collections::HashMap,
    net::Ipv4Addr,
    sync::{Arc, Mutex},
};

use controller::{identifier_controller::IdentifierController, utils::OptionalConfig, Controller};
use keri::{
    actor::{error::ActorError, simple_controller::SimpleController},
    database::{escrow::EscrowDb, SledEventDatabase},
    error::Error,
    event_parsing::codes::self_signing::SelfSigning,
    oobi::LocationScheme,
    prefix::{BasicPrefix, IdentifierPrefix, SelfSigningPrefix},
    signer::{CryptoBox, KeyManager},
    transport::{
        default::DefaultTransport,
        test::{TestActorMap, TestTransport},
    },
};
use tempfile::Builder;
use url::{Host, Url};
use witness::WitnessListener;

use crate::{watcher::WatcherData, WatcherListener};

#[async_std::test]
async fn test_authentication() -> Result<(), Error> {
    // Controller who will ask
    let mut asker_controller = {
        // Create test db and event processor.
        let root = Builder::new().prefix("test-db1").tempdir().unwrap();
        std::fs::create_dir_all(root.path()).unwrap();
        let db_controller = Arc::new(SledEventDatabase::new(root.path()).unwrap());

        let escrow_root = Builder::new().prefix("test-db-escrow1").tempdir().unwrap();
        let escrow_db = Arc::new(EscrowDb::new(escrow_root.path()).unwrap());

        let oobi_root = Builder::new().prefix("oobi-test-db1").tempdir().unwrap();

        let key_manager = {
            use keri::signer::CryptoBox;
            Arc::new(Mutex::new(CryptoBox::new().unwrap()))
        };
        SimpleController::new(
            Arc::clone(&db_controller),
            escrow_db,
            key_manager,
            oobi_root.path(),
        )
        .unwrap()
    };

    let asker_icp = asker_controller
        .incept(None, None, None)
        .unwrap()
        .serialize()
        .unwrap();

    // Controller about witch we will ask
    let mut about_controller = {
        // Create test db and event processor.
        let root = Builder::new().prefix("test-db2").tempdir().unwrap();
        let db_controller = Arc::new(SledEventDatabase::new(root.path()).unwrap());

        let escrow_root = Builder::new().prefix("test-db-escrow2").tempdir().unwrap();
        let escrow_db = Arc::new(EscrowDb::new(escrow_root.path()).unwrap());

        let oobi_root = Builder::new().prefix("oobi-test-db2").tempdir().unwrap();

        let key_manager = {
            use keri::signer::CryptoBox;
            Arc::new(Mutex::new(CryptoBox::new().unwrap()))
        };
        SimpleController::new(
            Arc::clone(&db_controller),
            escrow_db,
            key_manager,
            oobi_root.path(),
        )
        .unwrap()
    };

    let about_icp = about_controller
        .incept(None, None, None)
        .unwrap()
        .serialize()
        .unwrap();

    let url = Url::parse("http://some/dummy/url").unwrap();
    let root = Builder::new().prefix("cont-test-db").tempdir().unwrap();
    let watcher = WatcherData::setup(url, root.path(), None, Box::new(DefaultTransport::new()))?;

    // Watcher should know both controllers
    watcher.parse_and_process_notices(&asker_icp).unwrap();
    watcher.parse_and_process_notices(&about_icp).unwrap();

    let query = asker_controller.query_ksn(about_controller.prefix())?;

    // Send query message to watcher before sending end role oobi
    let err = watcher.process_op(query.clone()).await;

    assert!(matches!(err, Err(ActorError::MissingRole { .. })));

    // Create and send end role oobi to watcher
    let end_role =
        asker_controller.add_watcher(&IdentifierPrefix::Basic(watcher.prefix.clone()))?;
    watcher.process_op(end_role).await.unwrap();

    // Send query again
    let result = watcher.process_op(query).await;
    // Expect error because controller's witness config is empty and latest ksn can't be checked.
    assert!(matches!(
        result, Err(ActorError::NoIdentState { ref prefix })
        if prefix == about_controller.prefix()
    ));

    Ok(())
}

#[ignore]
#[async_std::test]
async fn test_add_watcher() -> Result<(), Error> {
    let wit = {
        let wit_root = Builder::new().prefix("wit-db").tempdir().unwrap();
        WitnessListener::setup(
            Url::parse("http://127.0.0.1:3232").unwrap(),
            None,
            wit_root.path(),
            Some("ArwXoACJgOleVZ2PY7kXn7rA0II0mHYDhc6WrBH8fDAc".to_string()),
        )?
    };

    let watcher_url = Url::parse("http://127.0.0.1:3236").unwrap();
    let watcher_listener = {
        let root = Builder::new().prefix("cont-test-db").tempdir().unwrap();
        WatcherListener::setup(watcher_url.clone(), None, root.path(), None)?
    };
    let watcher = watcher_listener.watcher_data.clone();
    let watcher_id = watcher.0.prefix.clone();
    // let watcher_id: BasicPrefix = "BF2t2NPc1bwptY1hYV0YCib1JjQ11k9jtuaZemecPF5b".parse().unwrap();

    let mut actors: TestActorMap = HashMap::new();
    actors.insert((Host::Ipv4(Ipv4Addr::LOCALHOST), 3232), Arc::new(wit));
    actors.insert(
        (Host::Ipv4(Ipv4Addr::LOCALHOST), 3236),
        Arc::new(watcher_listener),
    );
    let transport = TestTransport::new(actors);

    let root = Builder::new().prefix("test-db").tempdir().unwrap();
    let initial_config = OptionalConfig::init().with_db_path(root.into_path());
    let controller =
        Arc::new(Controller::with_transport(Some(initial_config), Box::new(transport)).unwrap());
    let km1 = CryptoBox::new()?;
    let km2 = CryptoBox::new()?;

    let mut identifier1 = {
        let pk = BasicPrefix::Ed25519(km1.public_key());
        let npk = BasicPrefix::Ed25519(km1.next_public_key());

        let icp_event = controller
            .incept(vec![pk], vec![npk], vec![], 0)
            .await
            .unwrap();
        let signature = SelfSigningPrefix::Ed25519Sha512(km1.sign(icp_event.as_bytes())?);

        let incepted_identifier = controller
            .finalize_inception(icp_event.as_bytes(), &signature)
            .await
            .unwrap();
        IdentifierController::new(incepted_identifier, controller.clone())
    };

    let identifier2 = {
        let pk = BasicPrefix::Ed25519(km2.public_key());
        let npk = BasicPrefix::Ed25519(km2.next_public_key());

        let icp_event = controller
            .incept(vec![pk], vec![npk], vec![], 0)
            .await
            .unwrap();
        let signature = SelfSigningPrefix::Ed25519Sha512(km2.sign(icp_event.as_bytes())?);

        let incepted_identifier = controller
            .finalize_inception(icp_event.as_bytes(), &signature)
            .await
            .unwrap();
        IdentifierController::new(incepted_identifier, controller.clone())
    };

    // Watcher should know both controllers
    // watcher.parse_and_process_notices(&asker_icp).unwrap();
    // watcher.parse_and_process_notices(&about_icp).unwrap();

    let watcher_oobi = LocationScheme {
        eid: IdentifierPrefix::Basic(watcher_id.clone()),
        scheme: keri::oobi::Scheme::Http,
        url: watcher_url,
    };
    identifier1
        .source
        .resolve_loc_schema(&watcher_oobi)
        .await
        .unwrap();

    let add_watcher = identifier1
        .add_watcher(IdentifierPrefix::Basic(watcher_id.clone()))
        .unwrap();
    let query_sig = SelfSigningPrefix::new(
        SelfSigning::Ed25519Sha512,
        km1.sign(add_watcher.as_bytes()).unwrap(),
    );
    identifier1
        .finalize_event(add_watcher.as_bytes(), query_sig)
        .await
        .unwrap();

    let query = identifier1
        .query_watcher(&identifier2.id, IdentifierPrefix::Basic(watcher_id))
        .unwrap();
    let query_sig = SelfSigningPrefix::new(
        SelfSigning::Ed25519Sha512,
        km1.sign(&query.serialize()?).unwrap(),
    );
    identifier1
        .finalize_query(vec![(query, query_sig)])
        .await
        .unwrap();

    Ok(())
}
