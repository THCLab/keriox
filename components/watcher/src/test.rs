#![cfg(test)]

use std::sync::{Arc, Mutex};

use controller::{identifier_controller::IdentifierController, utils::OptionalConfig, Controller};
use keri::{
    actor::simple_controller::SimpleController,
    database::{escrow::EscrowDb, SledEventDatabase},
    error::Error,
    event_parsing::codes::self_signing::SelfSigning,
    oobi::LocationScheme,
    prefix::{BasicPrefix, IdentifierPrefix, SelfSigningPrefix},
    signer::{CryptoBox, KeyManager},
};
use keri_transport::default::DefaultTransport;
use tempfile::Builder;

use crate::watcher::{WatcherData, WatcherError};

#[test]
pub fn test_authentication() -> Result<(), Error> {
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
            key_manager.clone(),
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
            key_manager.clone(),
            oobi_root.path(),
        )
        .unwrap()
    };

    let about_icp = about_controller
        .incept(None, None, None)
        .unwrap()
        .serialize()
        .unwrap();

    let url = url::Url::parse("http://some/dummy/url").unwrap();
    let root = Builder::new().prefix("cont-test-db").tempdir().unwrap();
    let watcher = WatcherData::setup(url, root.path(), None, Box::new(DefaultTransport::new()))?;

    // Watcher should know both controllers
    watcher.parse_and_process_notices(&asker_icp).unwrap();
    watcher.parse_and_process_notices(&about_icp).unwrap();

    let query = asker_controller.query_ksn(about_controller.prefix())?;

    // Send query message to watcher before sending end role oobi
    let err = futures::executor::block_on(watcher.process_op(query.clone()));

    assert!(matches!(err, Err(WatcherError::MissingRole { .. })));

    // Create and send end role oobi to watcher
    let end_role =
        asker_controller.add_watcher(&IdentifierPrefix::Basic(watcher.prefix.clone()))?;
    futures::executor::block_on(watcher.process_op(end_role)).unwrap();

    // Send query again
    let result = futures::executor::block_on(watcher.process_op(query));
    // Expect error because controller's witness config is empty and latest ksn can't be checked.
    assert!(matches!(
        result, Err(WatcherError::NoIdentState { ref prefix })
        if prefix == about_controller.prefix()
    ));

    Ok(())
}

#[ignore]
#[test]
fn test_add_watcher() -> Result<(), Error> {
    let root = Builder::new().prefix("test-db").tempdir().unwrap();
    let initial_config = OptionalConfig::init().with_db_path(root.into_path());

    let controller = Arc::new(Controller::new(Some(initial_config)).unwrap());
    let km1 = CryptoBox::new()?;
    let km2 = CryptoBox::new()?;

    let mut identifier1 = {
        let pk = BasicPrefix::Ed25519(km1.public_key());
        let npk = BasicPrefix::Ed25519(km1.next_public_key());

        let icp_event =
            futures::executor::block_on(controller.incept(vec![pk], vec![npk], vec![], 0)).unwrap();
        let signature = SelfSigningPrefix::Ed25519Sha512(km1.sign(icp_event.as_bytes())?);

        let incepted_identifier = futures::executor::block_on(
            controller.finalize_inception(icp_event.as_bytes(), &signature),
        )
        .unwrap();
        IdentifierController::new(incepted_identifier, controller.clone())
    };

    let identifier2 = {
        let pk = BasicPrefix::Ed25519(km2.public_key());
        let npk = BasicPrefix::Ed25519(km2.next_public_key());

        let icp_event =
            futures::executor::block_on(controller.incept(vec![pk], vec![npk], vec![], 0)).unwrap();
        let signature = SelfSigningPrefix::Ed25519Sha512(km2.sign(icp_event.as_bytes())?);

        let incepted_identifier = futures::executor::block_on(
            controller.finalize_inception(icp_event.as_bytes(), &signature),
        )
        .unwrap();
        IdentifierController::new(incepted_identifier, controller.clone())
    };

    let url = url::Url::parse("http://127.0.0.1:3236").unwrap();
    let root = Builder::new().prefix("cont-test-db").tempdir().unwrap();
    let watcher = WatcherData::setup(
        url.clone(),
        root.path(),
        None,
        Box::new(DefaultTransport::new()),
    )?;
    let watcher_id = watcher.prefix;
    // let watcher_id: BasicPrefix = "BF2t2NPc1bwptY1hYV0YCib1JjQ11k9jtuaZemecPF5b".parse().unwrap();

    // Watcher should know both controllers
    // watcher.parse_and_process_notices(&asker_icp).unwrap();
    // watcher.parse_and_process_notices(&about_icp).unwrap();

    let watcher_oobi = LocationScheme {
        eid: IdentifierPrefix::Basic(watcher_id.clone()),
        scheme: keri::oobi::Scheme::Http,
        url,
    };
    futures::executor::block_on(identifier1.source.resolve_loc_schema(&watcher_oobi)).unwrap();

    let add_watcher = identifier1
        .add_watcher(IdentifierPrefix::Basic(watcher_id.clone()))
        .unwrap();
    let query_sig = SelfSigningPrefix::new(
        SelfSigning::Ed25519Sha512,
        km1.sign(add_watcher.as_bytes()).unwrap(),
    );
    futures::executor::block_on(identifier1.finalize_event(add_watcher.as_bytes(), query_sig))
        .unwrap();

    let query = identifier1
        .query_watcher(&identifier2.id, IdentifierPrefix::Basic(watcher_id))
        .unwrap();
    let query_sig = SelfSigningPrefix::new(
        SelfSigning::Ed25519Sha512,
        km1.sign(&query.serialize()?).unwrap(),
    );
    futures::executor::block_on(identifier1.finalize_query(vec![(query, query_sig)])).unwrap();

    Ok(())
}
