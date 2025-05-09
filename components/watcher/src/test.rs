use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use keri_controller::SelfSigningPrefix;
use keri_core::{
    actor::{
        error::ActorError, possible_response::PossibleResponse,
        simple_controller::SimpleController, SignedQueryError,
    },
    database::redb::RedbDatabase,
    event_message::signed_event_message::{Notice, Op},
    prefix::IdentifierPrefix,
    processor::escrow::EscrowConfig,
    query::{
        query_event::{SignedKelQuery, SignedQueryMessage},
        reply_event::SignedReply,
    },
    transport::test::{TestActorMap, TestTransport},
};
use tempfile::Builder;
use url::{Host, Url};
use witness::{WitnessEscrowConfig, WitnessListener};

use crate::{Watcher, WatcherConfig};

#[actix_web::test]
async fn test_watcher_access() -> Result<(), ActorError> {
    // Controller who will ask
    let mut asker_controller = {
        // Create test db and event processor.
        let events_db_path = Builder::new().tempfile().unwrap();
        let events_db = Arc::new(RedbDatabase::new(events_db_path.path()).unwrap());

        let key_manager = {
            use keri_core::signer::CryptoBox;
            Arc::new(Mutex::new(CryptoBox::new().unwrap()))
        };
        SimpleController::new(Arc::clone(&events_db), key_manager, EscrowConfig::default()).unwrap()
    };

    let asker_icp = asker_controller
        .incept(None, None, None)
        .unwrap()
        .encode()
        .unwrap();

    // Controller about witch we will ask
    let mut about_controller = {
        // Create test db and event processor.
        let events_db_path = Builder::new().tempfile().unwrap();
        let events_db = Arc::new(RedbDatabase::new(events_db_path.path()).unwrap());

        let key_manager = {
            use keri_core::signer::CryptoBox;
            Arc::new(Mutex::new(CryptoBox::new().unwrap()))
        };
        SimpleController::new(Arc::clone(&events_db), key_manager, EscrowConfig::default()).unwrap()
    };

    let about_icp = about_controller
        .incept(None, None, None)
        .unwrap()
        .encode()
        .unwrap();

    let watcher_tel_dir = Builder::new().prefix("cont-test-tel-db").tempdir().unwrap();
    let watcher_tel_path = watcher_tel_dir.path().join("tel_storage");

    let url = Url::parse("http://some/dummy/url").unwrap();
    let root = Builder::new().prefix("cont-test-db").tempdir().unwrap();
    let watcher = Watcher::new(crate::WatcherConfig {
        public_address: url,
        db_path: root.path().to_owned(),
        tel_storage_path: watcher_tel_path,
        ..Default::default()
    })?;

    // Watcher should know both controllers
    watcher.parse_and_process_notices(&asker_icp).unwrap();
    watcher.parse_and_process_notices(&about_icp).unwrap();

    let query = asker_controller.query_ksn(about_controller.prefix())?;

    // Send query message to watcher before sending end role oobi
    let err = watcher.watcher_data.process_op(query.clone()).await;

    assert!(matches!(err, Err(ActorError::MissingRole { .. })));

    // Create and send end role oobi to watcher
    let end_role = asker_controller.add_watcher(&IdentifierPrefix::Basic(watcher.prefix()))?;
    watcher.watcher_data.process_op(end_role).await.unwrap();

    // Send query again
    let result = watcher.watcher_data.process_op(query).await;
    assert!(&result.is_ok());

    Ok(())
}

#[actix_web::test]
pub async fn watcher_forward_ksn() -> Result<(), ActorError> {
    let witness_url = url::Url::parse("http://witness1").unwrap();

    let witness_listener = {
        let root_witness = Builder::new().prefix("test-wit").tempdir().unwrap();

        Arc::new(
            WitnessListener::setup(
                witness_url,
                root_witness.path(),
                Some("ArwXoACJgOleVZ2PY7kXn7rA0II0mHYDhc6WrBH8fDAc".into()),
                WitnessEscrowConfig::default(),
            )
            .unwrap(),
        )
    };

    // Controller who will ask
    let mut asker_controller = {
        // Create test db and event processor.
        let root = Builder::new().prefix("test-db1").tempdir().unwrap();
        std::fs::create_dir_all(root.path()).unwrap();
        let events_db_path = Builder::new().tempfile().unwrap();
        let events_db = Arc::new(RedbDatabase::new(events_db_path.path()).unwrap());

        let key_manager = {
            use keri_core::signer::CryptoBox;
            Arc::new(Mutex::new(CryptoBox::new().unwrap()))
        };
        SimpleController::new(Arc::clone(&events_db), key_manager, EscrowConfig::default()).unwrap()
    };

    let asker_icp = asker_controller.incept(None, None, None).unwrap();

    // Controller about which we will ask
    let mut about_controller = {
        // Create test db and event processor.
        let events_db_path = Builder::new().tempfile().unwrap();
        let events_db = Arc::new(RedbDatabase::new(events_db_path.path()).unwrap());

        let key_manager = {
            use keri_core::signer::CryptoBox;
            Arc::new(Mutex::new(CryptoBox::new().unwrap()))
        };
        SimpleController::new(Arc::clone(&events_db), key_manager, EscrowConfig::default()).unwrap()
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
    let watcher_tel_dir = Builder::new().prefix("cont-test-tel-db").tempdir().unwrap();
    let watcher_tel_path = watcher_tel_dir.path().join("tel_storage");

    let watcher = Watcher::new(WatcherConfig {
        public_address: url,
        db_path: root.path().to_owned(),
        transport: Box::new(transport),
        tel_storage_path: watcher_tel_path,
        ..Default::default()
    })?;

    // Watcher should know both controllers
    watcher
        .parse_and_process_notices(&asker_icp.encode().unwrap())
        .unwrap();
    watcher
        .parse_and_process_notices(&about_icp.encode().unwrap())
        .unwrap();

    let query = asker_controller.query_ksn(about_controller.prefix())?;

    // Send query message to watcher before sending end role oobi
    let err = watcher.watcher_data.process_op(query.clone()).await;

    assert!(matches!(err, Err(ActorError::MissingRole { .. })));

    // Create and send end role oobi to watcher
    let end_role = asker_controller.add_watcher(&IdentifierPrefix::Basic(watcher.prefix()))?;
    watcher.watcher_data.process_op(end_role).await.unwrap();

    // Send query again
    let _result = watcher
        .watcher_data
        .process_op(query.clone())
        .await
        .unwrap();
    // Expect error because no loc scheme for witness.
    // assert!(matches!(
    //     result, Err(ActorError::NoLocation { ref id })
    //     if id == &IdentifierPrefix::Basic(witness.prefix.clone())
    // ));

    // Send witness' OOBI to watcher
    let witness_oobis = witness
        .oobi_manager
        .get_loc_scheme(&IdentifierPrefix::Basic(witness.prefix.clone()))
        .unwrap();
    let witness_oobi = SignedReply::new_nontrans(
        witness_oobis[0].clone(),
        witness.prefix.clone(),
        SelfSigningPrefix::Ed25519Sha512(
            witness
                .signer
                .sign(witness_oobis[0].encode().unwrap())
                .unwrap(),
        ),
    );
    watcher.watcher_data.process_reply(witness_oobi).unwrap();

    let mut wrong_query = query.clone();
    if let Op::Query(SignedQueryMessage::KelQuery(SignedKelQuery { signature, .. })) =
        &mut wrong_query
    {
        match signature {
            keri_core::event_message::signature::Signature::Transferable(_, sig) => {
                if let SelfSigningPrefix::Ed25519Sha512(ref mut bytes) = &mut sig[0].signature {
                    bytes[15] += 1;
                } else {
                    panic!("Unexpected signature type");
                }
            }
            keri_core::event_message::signature::Signature::NonTransferable(_) => unreachable!(),
        };
    }

    // Send wrong query
    let result = watcher.watcher_data.process_op(wrong_query).await;

    assert!(matches!(
        result,
        Err(ActorError::QueryError(
            SignedQueryError::InvalidSignature { .. }
        ))
    ));

    // Send query again
    let result = watcher.watcher_data.process_op(query).await;

    assert!(matches!(
        result,
        Ok(Some(PossibleResponse::Ksn(SignedReply { .. })))
    ));

    Ok(())
}
