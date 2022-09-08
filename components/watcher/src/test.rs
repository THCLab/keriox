#![cfg(test)]

use std::sync::{Arc, Mutex};

use keri::{
    actor::simple_controller::SimpleController,
    database::{escrow::EscrowDb, SledEventDatabase},
    error::Error,
    prefix::IdentifierPrefix,
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
        .incept(None, None)
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
        .incept(None, None)
        .unwrap()
        .serialize()
        .unwrap();

    let url = url::Url::parse("http://some/dummy/url").unwrap();
    let root = Builder::new().prefix("cont-test-db").tempdir().unwrap();
    let watcher = WatcherData::setup(url, root.path(), None, Box::new(DefaultTransport))?;

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
