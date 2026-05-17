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
    let watcher = Watcher::setup_with_redb(crate::WatcherConfig {
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
            WitnessListener::setup_with_redb(
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

    let watcher = Watcher::setup_with_redb(WatcherConfig {
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

/// Regression test for the http→https loc-scheme migration bug.
///
/// When a witness migrates its self-advertised scheme (e.g. http→https)
/// both signed reply events stay in the OOBI store. Before the fix the
/// watcher returned them in lexicographic key order — `"http"` sorts
/// before `"https"` byte-by-byte — and `.get(0)` / hardcoded
/// `Scheme::Http` lookups deterministically pinned every subsequent
/// query at the stale endpoint. After the fix the watcher must pick
/// the reply with the latest `dt` regardless of scheme, matching
/// what `bada_logic` already enforces at ingest time.
///
/// This test stores two valid signed loc replies for the same eid
/// (http with the older `dt`, https with the newer one), feeds them to
/// the watcher via `process_reply`, and asserts `latest_loc_scheme`
/// returns the https one. Order of insertion is exercised both ways so
/// a future change that re-introduces "first row wins" fails here
/// regardless of which reply lands in the store first.
#[actix_web::test]
async fn latest_loc_scheme_picks_newest_dt() -> Result<(), ActorError> {
    use keri_core::{
        event_message::msg::KeriEvent,
        event_message::timestamped::Timestamped,
        oobi::{LocationScheme, Scheme},
        query::reply_event::{ReplyEvent, ReplyRoute, SignedReply},
        prefix::BasicPrefix,
        signer::Signer,
    };
    use keri_controller::SelfSigningPrefix;
    use chrono::{DateTime, FixedOffset, TimeZone};
    use keri_core::actor::prelude::{HashFunctionCode, SerializationFormats};

    // A witness identity: any Ed25519 keypair will do — the watcher only
    // checks that signatures on the loc replies verify against the eid,
    // not that the eid is a real running witness.
    let witness_signer = Signer::new();
    let witness_pk = witness_signer.public_key();
    let witness_prefix = BasicPrefix::Ed25519(witness_pk);
    let witness_eid = IdentifierPrefix::Basic(witness_prefix.clone());

    // Spin up a watcher with on-disk redb so the OOBI manager exercises
    // the same storage path production uses.
    let root = Builder::new().prefix("watcher-loc-scheme-test").tempdir().unwrap();
    let watcher_tel_dir = Builder::new().prefix("watcher-loc-scheme-tel").tempdir().unwrap();
    let watcher_tel_path = watcher_tel_dir.path().join("tel_storage");
    let dummy_public = Url::parse("http://watcher-under-test/").unwrap();
    let watcher = Watcher::setup_with_redb(WatcherConfig {
        public_address: dummy_public,
        db_path: root.path().to_owned(),
        tel_storage_path: watcher_tel_path,
        ..Default::default()
    })?;

    // Build two LocScheme reply events for the same witness with
    // explicit, well-ordered timestamps. We construct the Timestamped
    // wrapper manually so the test does not depend on wall-clock
    // resolution to separate the two replies — that flakes on fast
    // machines with the default `Timestamped::new(...)`.
    let make_reply = |scheme: Scheme, url: &str, dt: DateTime<FixedOffset>| -> SignedReply {
        let loc = LocationScheme::new(witness_eid.clone(), scheme, Url::parse(url).unwrap());
        // `ReplyEvent::new_reply` uses `Utc::now()` internally; rebuild
        // through `KeriEvent::new` so we get a deterministic `dt`.
        let env = Timestamped {
            timestamp: dt,
            data: ReplyRoute::LocScheme(loc),
        };
        let reply: ReplyEvent = KeriEvent::new(
            SerializationFormats::JSON,
            HashFunctionCode::Blake3_256.into(),
            env,
        );
        let sig_bytes = witness_signer.sign(reply.encode().unwrap()).unwrap();
        SignedReply::new_nontrans(
            reply,
            witness_prefix.clone(),
            SelfSigningPrefix::Ed25519Sha512(sig_bytes),
        )
    };

    let dt_old: DateTime<FixedOffset> = FixedOffset::east_opt(0)
        .unwrap()
        .with_ymd_and_hms(2026, 4, 18, 6, 34, 3)
        .single()
        .unwrap();
    let dt_new: DateTime<FixedOffset> = FixedOffset::east_opt(0)
        .unwrap()
        .with_ymd_and_hms(2026, 5, 6, 6, 1, 23)
        .single()
        .unwrap();

    let http_reply = make_reply(Scheme::Http, "http://witness-under-test/", dt_old);
    let https_reply = make_reply(Scheme::Https, "https://witness-under-test/", dt_new);

    // Case 1: ingest http first, then https. https has the newer dt
    // so it must win regardless of which row redb ranges first.
    watcher.watcher_data.process_reply(http_reply.clone()).unwrap();
    watcher.watcher_data.process_reply(https_reply.clone()).unwrap();

    let picked = watcher.watcher_data.latest_loc_scheme(&witness_eid)?;
    assert_eq!(picked.scheme, Scheme::Https,
        "after a http→https migration the newer-dt reply must win even though \
         redb stores http under a lexicographically-smaller scheme key");
    assert_eq!(picked.url.as_str(), "https://witness-under-test/");

    // Case 2: insertion order should not affect the outcome. Use a
    // fresh watcher so the previous replies don't leak in.
    let root2 = Builder::new().prefix("watcher-loc-scheme-test-2").tempdir().unwrap();
    let watcher_tel_dir2 = Builder::new().prefix("watcher-loc-scheme-tel-2").tempdir().unwrap();
    let watcher_tel_path2 = watcher_tel_dir2.path().join("tel_storage");
    let watcher2 = Watcher::setup_with_redb(WatcherConfig {
        public_address: Url::parse("http://watcher-under-test-2/").unwrap(),
        db_path: root2.path().to_owned(),
        tel_storage_path: watcher_tel_path2,
        ..Default::default()
    })?;
    watcher2.watcher_data.process_reply(https_reply.clone()).unwrap();
    watcher2.watcher_data.process_reply(http_reply.clone()).unwrap();

    let picked2 = watcher2.watcher_data.latest_loc_scheme(&witness_eid)?;
    assert_eq!(picked2.scheme, Scheme::Https,
        "insertion order must not influence the selection");
    assert_eq!(picked2.url.as_str(), "https://witness-under-test/");

    // Case 3: empty OOBI store yields NoLocation, not a panic or stale
    // value. Use yet another fresh watcher so the assertion does not
    // depend on test execution order.
    let root3 = Builder::new().prefix("watcher-loc-scheme-test-3").tempdir().unwrap();
    let watcher_tel_dir3 = Builder::new().prefix("watcher-loc-scheme-tel-3").tempdir().unwrap();
    let watcher_tel_path3 = watcher_tel_dir3.path().join("tel_storage");
    let watcher3 = Watcher::setup_with_redb(WatcherConfig {
        public_address: Url::parse("http://watcher-under-test-3/").unwrap(),
        db_path: root3.path().to_owned(),
        tel_storage_path: watcher_tel_path3,
        ..Default::default()
    })?;
    let unknown_eid = IdentifierPrefix::Basic(BasicPrefix::Ed25519(Signer::new().public_key()));
    let err = watcher3.watcher_data.latest_loc_scheme(&unknown_eid);
    assert!(
        matches!(err, Err(ActorError::NoLocation { ref id }) if id == &unknown_eid),
        "expected NoLocation for unknown eid, got {err:?}"
    );

    Ok(())
}
