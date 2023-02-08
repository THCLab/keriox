use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::Duration,
};

use keri::{
    actor::{
        error::ActorError,
        simple_controller::{PossibleResponse, SimpleController},
        SignedQueryError,
    },
    database::{escrow::EscrowDb, SledEventDatabase},
    error::Error,
    event_message::signed_event_message::{Notice, Op},
    prefix::{IdentifierPrefix, SelfSigningPrefix},
    query::{query_event::SignedQuery, reply_event::SignedReply},
    transport::test::{TestActorMap, TestTransport},
};
use tempfile::Builder;
use url::Host;
use watcher::{WatcherConfig, WatcherData};
use witness::WitnessListener;

#[test]
pub fn watcher_forward_ksn() -> Result<(), Error> {
    let witness_url = url::Url::parse("http://witness1").unwrap();

    let witness_listener = {
        let root_witness = Builder::new().prefix("test-wit").tempdir().unwrap();

        Arc::new(WitnessListener::setup(
            witness_url,
            root_witness.path(),
            Some("ArwXoACJgOleVZ2PY7kXn7rA0II0mHYDhc6WrBH8fDAc".into()),
            Duration::from_secs(60),
        )?)
    };

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
            Duration::from_secs(60),
        )
        .unwrap()
    };

    let asker_icp = asker_controller.incept(None, None, None).unwrap();

    // Controller about which we will ask
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
            Duration::from_secs(60),
        )
        .unwrap()
    };

    let about_icp = about_controller
        .incept(Some(vec![witness_listener.get_prefix()]), Some(0), None)
        .unwrap();

    witness_listener
        .witness_data
        .process_notice(Notice::Event(about_icp.clone()))
        .unwrap();

    let witness = Arc::clone(&witness_listener.witness_data);

    let mut actors: TestActorMap = HashMap::new();
    actors.insert((Host::Domain("witness1".to_string()), 80), witness_listener);
    let transport = TestTransport::new(actors);

    let url = url::Url::parse("http://some/dummy/url").unwrap();
    let root = Builder::new().prefix("cont-test-db").tempdir().unwrap();
    let watcher = WatcherData::new(WatcherConfig {
        public_address: url,
        db_path: root.path().to_owned(),
        transport: Box::new(transport),
        ..Default::default()
    })?;

    // Watcher should know both controllers
    watcher
        .parse_and_process_notices(&asker_icp.serialize().unwrap())
        .unwrap();
    watcher
        .parse_and_process_notices(&about_icp.serialize().unwrap())
        .unwrap();

    let query = asker_controller.query_ksn(about_controller.prefix())?;

    // Send query message to watcher before sending end role oobi
    let err = futures::executor::block_on(watcher.process_op(query.clone()));

    assert!(matches!(err, Err(ActorError::MissingRole { .. })));

    // Create and send end role oobi to watcher
    let end_role =
        asker_controller.add_watcher(&IdentifierPrefix::Basic(watcher.prefix.clone()))?;
    futures::executor::block_on(watcher.process_op(end_role)).unwrap();

    // Send query again
    let result = futures::executor::block_on(watcher.process_op(query.clone()));
    // Expect error because no loc scheme for witness.
    assert!(matches!(
        result, Err(ActorError::NoLocation { ref id })
        if id == &IdentifierPrefix::Basic(witness.prefix.clone())
    ));

    // Send witness' OOBI to watcher
    let witness_oobis = witness
        .oobi_manager
        .get_loc_scheme(&IdentifierPrefix::Basic(witness.prefix.clone()))
        .unwrap()
        .unwrap();
    let witness_oobi = SignedReply::new_nontrans(
        witness_oobis[0].clone(),
        witness.prefix.clone(),
        SelfSigningPrefix::Ed25519Sha512(
            witness
                .signer
                .sign(witness_oobis[0].serialize().unwrap())
                .unwrap(),
        ),
    );
    watcher.process_reply(witness_oobi).unwrap();

    let mut wrong_query = query.clone();
    if let Op::Query(SignedQuery { signatures, .. }) = &mut wrong_query {
        if let SelfSigningPrefix::Ed25519Sha512(ref mut bytes) = &mut signatures[0].signature {
            bytes[15] += 1;
        } else {
            panic!("Unexpected signature type");
        }
    }

    // Send wrong query
    let result = futures::executor::block_on(watcher.process_op(wrong_query));

    assert!(matches!(
        result,
        Err(ActorError::QueryError(
            SignedQueryError::InvalidSignature { .. }
        ))
    ));

    // Send query again
    let result = futures::executor::block_on(watcher.process_op(query));

    assert!(matches!(
        result,
        Ok(Some(PossibleResponse::Ksn(SignedReply { .. })))
    ));

    Ok(())
}
