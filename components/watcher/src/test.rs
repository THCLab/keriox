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
                keri_core::event_message::keri_version::KeriVersion::V1_0,
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

    // A witness identity: any non-transferable Ed25519 key will do — the watcher only
    // checks that signatures on the loc replies verify against the eid,
    // not that the eid is a real running witness.
    let witness_signer = Signer::new();
    let witness_pk = witness_signer.public_key();
    let witness_prefix = BasicPrefix::Ed25519NT(witness_pk);
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
            sender: None,
            timestamp: dt,
            data: ReplyRoute::LocScheme(loc),
        };
        let reply: ReplyEvent = KeriEvent::new(
            keri_core::event_message::keri_version::KeriVersion::V1_0,
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
    assert_eq!(picked.url.unwrap().as_str(), "https://witness-under-test/");

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
    assert_eq!(picked2.url.unwrap().as_str(), "https://witness-under-test/");

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

    // Case 4: a newer tcp location (KERIpy witnesses advertise one next to
    // http) is not reachable by the watcher's transports, so the newest
    // http(s) location still wins.
    let dt_newest: DateTime<FixedOffset> = FixedOffset::east_opt(0)
        .unwrap()
        .with_ymd_and_hms(2026, 6, 1, 0, 0, 0)
        .single()
        .unwrap();
    let tcp_reply = make_reply(Scheme::Tcp, "tcp://witness-under-test:5632/", dt_newest);
    watcher.watcher_data.process_reply(tcp_reply).unwrap();

    let picked4 = watcher.watcher_data.latest_loc_scheme(&witness_eid)?;
    assert_eq!(
        picked4.scheme,
        Scheme::Https,
        "a tcp location must not displace a reachable http(s) one"
    );

    Ok(())
}

mod abandonment {
    use std::sync::Arc;

    use actix_web::{body::to_bytes, http::StatusCode, web};
    use keri_core::{
        event::{sections::threshold::SignatureThreshold, KeyEvent},
        event_message::{
            event_msg_builder::EventMsgBuilder, msg::KeriEvent, signed_event_message::Notice,
            EventTypeTag,
        },
        oobi_manager::RedbOobiStorage,
        prefix::{BasicPrefix, IdentifierPrefix, IndexedSignature, SelfSigningPrefix},
        signer::Signer,
    };
    use tempfile::{Builder, TempDir};
    use url::Url;

    use crate::{watcher_listener::http_handlers, Watcher, WatcherConfig};

    struct Fixture {
        _dirs: (TempDir, TempDir),
        watcher: Arc<Watcher<RedbOobiStorage>>,
    }

    fn setup() -> Fixture {
        let tel = Builder::new().prefix("watcher-tel").tempdir().unwrap();
        let db = Builder::new().prefix("watcher-db").tempdir().unwrap();
        let watcher = Watcher::setup_with_redb(WatcherConfig {
            public_address: Url::parse("http://some/dummy/url").unwrap(),
            db_path: db.path().to_owned(),
            tel_storage_path: tel.path().join("tel_storage"),
            ..Default::default()
        })
        .unwrap();
        Fixture {
            _dirs: (tel, db),
            watcher: Arc::new(watcher),
        }
    }

    fn key(signer: &Signer) -> BasicPrefix {
        BasicPrefix::Ed25519(signer.public_key())
    }

    fn signed(event: &KeriEvent<KeyEvent>, signer: &Signer) -> Notice {
        let sig = SelfSigningPrefix::Ed25519Sha512(signer.sign(event.encode().unwrap()).unwrap());
        Notice::Event(event.sign(vec![IndexedSignature::new_both_same(sig, 0)], None, None))
    }

    /// An identifier the watcher knows. It lists a witness the watcher has
    /// no location for, with threshold 0 so its events need no receipts:
    /// any attempt to ask that witness fails.
    struct Known {
        id: IdentifierPrefix,
        icp: KeriEvent<KeyEvent>,
        next: Signer,
    }

    fn incept(fx: &Fixture) -> Known {
        let (current, next) = (Signer::new(), Signer::new());
        let icp = EventMsgBuilder::new(EventTypeTag::Icp)
            .with_keys(vec![key(&current)])
            .with_next_keys(vec![key(&next)])
            .with_witness_list(&[BasicPrefix::Ed25519NT(Signer::new().public_key())])
            .with_witness_threshold(&SignatureThreshold::Simple(0))
            .build()
            .unwrap();
        fx.watcher
            .watcher_data
            .process_notice(signed(&icp, &current))
            .unwrap();
        Known {
            id: icp.data.get_prefix(),
            icp,
            next,
        }
    }

    fn abandon(fx: &Fixture, known: &Known) -> KeriEvent<KeyEvent> {
        let rot = EventMsgBuilder::new(EventTypeTag::Rot)
            .with_prefix(&known.id)
            .with_sn(1)
            .with_previous_event(&known.icp.digest().unwrap())
            .with_keys(vec![key(&known.next)])
            .with_next_keys(vec![])
            .with_next_threshold(&SignatureThreshold::Simple(0))
            .build()
            .unwrap();
        fx.watcher
            .watcher_data
            .process_notice(signed(&rot, &known.next))
            .unwrap();
        rot
    }

    /// A watcher restarted on its database still holds every log it had
    /// accepted; it used to empty the database file on start.
    #[actix_web::test]
    async fn a_restarted_watcher_keeps_the_logs_it_holds() {
        let fx = setup();
        let known = incept(&fx);
        let Fixture {
            _dirs: (tel, db),
            watcher,
        } = fx;
        drop(watcher);

        let watcher = Watcher::setup_with_redb(WatcherConfig {
            public_address: Url::parse("http://some/dummy/url").unwrap(),
            db_path: db.path().to_owned(),
            tel_storage_path: tel.path().join("tel_storage"),
            ..Default::default()
        })
        .unwrap();
        let state = watcher.watcher_data.event_storage.get_state(&known.id);
        assert_eq!(state.map(|s| s.sn), Some(0));
    }

    #[actix_web::test]
    async fn an_abandoned_identifier_is_not_polled() {
        let fx = setup();
        let poller = &fx.watcher.poller;

        let live = incept(&fx);
        poller.track_aid(live.id.clone());
        assert_eq!(poller.tracked_aid_ids(), vec![live.id.clone()]);

        // Abandoned after it was tracked: the next poll drops it, without
        // asking any witness.
        abandon(&fx, &live);
        poller.poll_due_aids().await;
        assert!(poller.tracked_aid_ids().is_empty());

        // Already abandoned: never tracked.
        poller.track_aid(live.id.clone());
        assert!(poller.tracked_aid_ids().is_empty());
    }

    #[actix_web::test]
    async fn updating_an_abandoned_log_asks_no_witness() {
        let fx = setup();
        let data = &fx.watcher.watcher_data;
        let known = incept(&fx);
        // Every attempt to ask the unreachable witness is a recorded failure.
        let failures = || -> u64 {
            data.health_tracker
                .get_all_health()
                .values()
                .map(|health| health.failures)
                .sum()
        };

        data.update_local_kel(&known.id).await.unwrap();
        assert_eq!(failures(), 1);

        abandon(&fx, &known);
        data.update_local_kel(&known.id).await.unwrap();
        assert_eq!(failures(), 1);
    }

    #[actix_web::test]
    async fn state_endpoint_reports_the_abandonment() {
        let fx = setup();
        let known = incept(&fx);
        let data = web::Data::new(fx.watcher.clone());
        let state = |id: IdentifierPrefix| {
            let data = data.clone();
            async move {
                let response = http_handlers::identifier_state(web::Path::from(id), data).await;
                let status = response.status();
                let body: serde_json::Value =
                    serde_json::from_slice(&to_bytes(response.into_body()).await.unwrap()).unwrap();
                (status, body)
            }
        };

        let (status, body) = state(known.id.clone()).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["abandoned"], serde_json::Value::Null);

        let rot = abandon(&fx, &known);
        let (status, body) = state(known.id.clone()).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["sn"], 1);
        assert_eq!(body["abandoned"]["said"], rot.digest().unwrap().to_string());

        let (status, _) = state(IdentifierPrefix::Basic(key(&Signer::new()))).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[actix_web::test]
    async fn info_advertises_abandonment_and_keri2() {
        let fx = setup();
        let response = http_handlers::info(web::Data::new(fx.watcher.clone())).await;
        let info: serde_json::Value =
            serde_json::from_slice(&to_bytes(response.into_body()).await.unwrap()).unwrap();
        let features = info["features"].as_array().unwrap();
        assert!(features.contains(&serde_json::json!("abandonment")));
        assert!(features.contains(&serde_json::json!("keri2")));
        assert_eq!(
            info["keri"],
            serde_json::json!({ "protocol": "1.0", "cesr_genus": "1.0" })
        );
    }

    #[actix_web::test]
    async fn info_reports_the_keri_version_the_watcher_writes() {
        let tel = Builder::new().prefix("watcher-tel").tempdir().unwrap();
        let db = Builder::new().prefix("watcher-db").tempdir().unwrap();
        let watcher = Watcher::setup_with_redb(WatcherConfig {
            public_address: Url::parse("http://some/dummy/url").unwrap(),
            db_path: db.path().to_owned(),
            tel_storage_path: tel.path().join("tel_storage"),
            keri_version: keri_core::event_message::keri_version::KeriVersion::V2_0,
            ..Default::default()
        })
        .unwrap();
        let response = http_handlers::info(web::Data::new(Arc::new(watcher))).await;
        let info: serde_json::Value =
            serde_json::from_slice(&to_bytes(response.into_body()).await.unwrap()).unwrap();
        assert_eq!(
            info["keri"],
            serde_json::json!({ "protocol": "2.0", "cesr_genus": "2.0" })
        );
    }
}

/// TEL queries reach the watcher's cached TEL for a credential, so they need
/// the same access control as KEL queries: a known signer with a watcher end
/// role and a signature that verifies over the query.
mod tel_query_access {
    use std::sync::{Arc, Mutex};

    use keri_controller::SelfSigningPrefix;
    use keri_core::{
        actor::{
            error::ActorError,
            prelude::{HashFunctionCode, SerializationFormats},
            simple_controller::SimpleController,
            SignedQueryError,
        },
        database::redb::RedbDatabase,
        event_message::{keri_version::KeriVersion, msg::KeriEvent, timestamped::Timestamped},
        oobi_manager::RedbOobiStorage,
        prefix::{IdentifierPrefix, IndexedSignature},
        processor::escrow::EscrowConfig,
        signer::{CryptoBox, KeyManager},
    };
    use teliox::query::{SignedTelQuery, TelQueryArgs, TelQueryEvent, TelQueryRoute};
    use tempfile::{Builder, TempDir};
    use url::Url;

    use crate::Watcher;

    struct Fixture {
        watcher: Watcher<RedbOobiStorage>,
        asker: SimpleController<CryptoBox, RedbDatabase, RedbOobiStorage>,
        _dirs: Vec<TempDir>,
    }

    fn setup() -> Fixture {
        let asker_db_dir = Builder::new().prefix("tel-qry-asker").tempdir().unwrap();
        let asker_db = Arc::new(RedbDatabase::new(&asker_db_dir.path().join("events")).unwrap());
        let keys = Arc::new(Mutex::new(CryptoBox::new().unwrap()));
        let mut asker = SimpleController::new(asker_db, keys, EscrowConfig::default()).unwrap();
        let asker_icp = asker.incept(None, None, None).unwrap().encode().unwrap();

        let root = Builder::new().prefix("tel-qry-watcher").tempdir().unwrap();
        let watcher = Watcher::setup_with_redb(crate::WatcherConfig {
            public_address: Url::parse("http://some/dummy/url").unwrap(),
            db_path: root.path().to_owned(),
            tel_storage_path: root.path().join("tel_storage"),
            ..Default::default()
        })
        .unwrap();
        watcher.parse_and_process_notices(&asker_icp).unwrap();

        Fixture {
            watcher,
            asker,
            _dirs: vec![asker_db_dir, root],
        }
    }

    fn tel_query() -> TelQueryEvent {
        let id: IdentifierPrefix = "EA8Ih8hxLi3mmkyItXK1u55cnHl4WgNZ_RE-gKXqgcX4"
            .parse()
            .unwrap();
        let ri: IdentifierPrefix = "EO0_SyqPS1-EVYSITakYpUHaUZZpZGsjaXFOaO_kCfS4"
            .parse()
            .unwrap();
        KeriEvent::new(
            KeriVersion::V1_0,
            SerializationFormats::JSON,
            HashFunctionCode::Blake3_256.into(),
            Timestamped::new(TelQueryRoute::Tels {
                reply_route: "".into(),
                args: TelQueryArgs {
                    i: Some(id),
                    ri: Some(ri),
                },
            }),
        )
    }

    fn signed_by(fx: &Fixture, qry: TelQueryEvent, signed_bytes: &[u8]) -> Vec<u8> {
        let sig = fx
            .asker
            .key_manager
            .lock()
            .unwrap()
            .sign(signed_bytes)
            .unwrap();
        SignedTelQuery::new_trans(
            qry,
            fx.asker.prefix().clone(),
            vec![IndexedSignature::new_both_same(
                SelfSigningPrefix::Ed25519Sha512(sig),
                0,
            )],
        )
        .to_cesr()
        .unwrap()
    }

    async fn grant_watcher_role(fx: &Fixture) {
        let end_role = fx
            .asker
            .add_watcher(&IdentifierPrefix::Basic(fx.watcher.prefix()))
            .unwrap();
        fx.watcher.watcher_data.process_op(end_role).await.unwrap();
    }

    #[actix_web::test]
    async fn a_signer_without_a_watcher_role_is_refused() {
        let fx = setup();
        let qry = tel_query();
        let stream = signed_by(&fx, qry.clone(), &qry.encode().unwrap());

        let result = fx
            .watcher
            .parse_and_process_tel_queries(&stream)
            .await
            .map(|replies| replies.len());

        assert!(
            matches!(result, Err(ActorError::MissingRole { .. })),
            "expected MissingRole, got {result:?}"
        );
    }

    #[actix_web::test]
    async fn a_signature_over_other_bytes_is_refused() {
        let fx = setup();
        grant_watcher_role(&fx).await;
        let qry = tel_query();
        let stream = signed_by(&fx, qry, b"some other message");

        let result = fx
            .watcher
            .parse_and_process_tel_queries(&stream)
            .await
            .map(|replies| replies.len());

        assert!(
            matches!(
                result,
                Err(ActorError::QueryError(SignedQueryError::InvalidSignature))
            ),
            "expected InvalidSignature, got {result:?}"
        );
    }

    #[actix_web::test]
    async fn a_signed_query_from_a_controller_with_the_role_is_answered() {
        let fx = setup();
        grant_watcher_role(&fx).await;
        let qry = tel_query();
        let stream = signed_by(&fx, qry.clone(), &qry.encode().unwrap());

        let result = fx
            .watcher
            .parse_and_process_tel_queries(&stream)
            .await
            .map(|replies| replies.len());

        assert!(result.is_ok(), "expected an answer, got {result:?}");
    }
}

/// Mailboxes are kept by witnesses, not watchers. A mailbox query sent to a
/// watcher is a misdirected request and must be refused, not crash the
/// handler serving it.
#[actix_web::test]
async fn a_mailbox_query_to_a_watcher_is_refused() {
    let controller_db_dir = Builder::new().prefix("mbx-qry-ctrl").tempdir().unwrap();
    let controller_db =
        Arc::new(RedbDatabase::new(&controller_db_dir.path().join("events")).unwrap());
    let key_manager = {
        use keri_core::signer::CryptoBox;
        Arc::new(Mutex::new(CryptoBox::new().unwrap()))
    };
    let mut controller =
        SimpleController::new(controller_db, key_manager, EscrowConfig::default()).unwrap();
    let icp = controller
        .incept(None, None, None)
        .unwrap()
        .encode()
        .unwrap();

    let root = Builder::new().prefix("mbx-qry-watcher").tempdir().unwrap();
    let watcher = Watcher::setup_with_redb(WatcherConfig {
        public_address: Url::parse("http://some/dummy/url").unwrap(),
        db_path: root.path().to_owned(),
        tel_storage_path: root.path().join("tel_storage"),
        ..Default::default()
    })
    .unwrap();
    watcher.parse_and_process_notices(&icp).unwrap();

    let mailbox_query = Op::Query(controller.query_mailbox(&watcher.prefix()));
    let stream = keri_core::event_message::signed_event_message::Message::Op(mailbox_query.clone())
        .to_cesr()
        .unwrap();

    let result = watcher.parse_and_process_queries(&stream).await;

    assert!(
        matches!(result, Err(ActorError::UnsupportedQuery(_))),
        "expected UnsupportedQuery, got {result:?}"
    );

    // Ops in a peer's answer to an end role OOBI go through process_op.
    let result = watcher.watcher_data.process_op(mailbox_query).await;

    assert!(
        matches!(result, Err(ActorError::UnsupportedQuery(_))),
        "expected UnsupportedQuery from process_op, got {result:?}"
    );
}
