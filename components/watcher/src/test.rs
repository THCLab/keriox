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

    let url = Url::parse("http://some/dummy/url").unwrap();
    let root = Builder::new().prefix("cont-test-db").tempdir().unwrap();
    let watcher = Watcher::setup_with_redb(crate::WatcherConfig {
        public_address: url,
        db_path: root.path().to_owned(),
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

    let watcher = Watcher::setup_with_redb(WatcherConfig {
        public_address: url,
        db_path: root.path().to_owned(),
        transport: Box::new(transport),
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
                    bytes[15] ^= 1;
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
    let dummy_public = Url::parse("http://watcher-under-test/").unwrap();
    let watcher = Watcher::setup_with_redb(WatcherConfig {
        public_address: dummy_public,
        db_path: root.path().to_owned(),
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
    let watcher2 = Watcher::setup_with_redb(WatcherConfig {
        public_address: Url::parse("http://watcher-under-test-2/").unwrap(),
        db_path: root2.path().to_owned(),
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
    let watcher3 = Watcher::setup_with_redb(WatcherConfig {
        public_address: Url::parse("http://watcher-under-test-3/").unwrap(),
        db_path: root3.path().to_owned(),
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
        _dir: TempDir,
        watcher: Arc<Watcher<RedbOobiStorage>>,
    }

    fn setup() -> Fixture {
        let db = Builder::new().prefix("watcher-db").tempdir().unwrap();
        let watcher = Watcher::setup_with_redb(WatcherConfig {
            public_address: Url::parse("http://some/dummy/url").unwrap(),
            db_path: db.path().to_owned(),
            ..Default::default()
        })
        .unwrap();
        Fixture {
            _dir: db,
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
            _dir: db,
            watcher,
        } = fx;
        drop(watcher);

        let watcher = Watcher::setup_with_redb(WatcherConfig {
            public_address: Url::parse("http://some/dummy/url").unwrap(),
            db_path: db.path().to_owned(),
            ..Default::default()
        })
        .unwrap();
        let state = watcher.watcher_data.event_storage.get_state(&known.id);
        assert_eq!(state.map(|s| s.sn), Some(0));
    }

    /// The identifiers a watcher polls, and which of them are subscribed,
    /// survive a restart; they used to live only in memory, so nothing was
    /// polled until clients sent their end role OOBIs again.
    #[actix_web::test]
    async fn a_restarted_watcher_keeps_polling_what_it_tracked() {
        let fx = setup();
        let (tracked, subscribed, untracked) = (incept(&fx), incept(&fx), incept(&fx));
        let poller = &fx.watcher.poller;
        poller.track_aid(tracked.id.clone());
        poller.subscribe(subscribed.id.clone());
        poller.track_aid(untracked.id.clone());
        poller.untrack_aid(&untracked.id);
        let Fixture {
            _dir: db,
            watcher,
        } = fx;
        drop(watcher);

        let watcher = Watcher::setup_with_redb(WatcherConfig {
            public_address: Url::parse("http://some/dummy/url").unwrap(),
            db_path: db.path().to_owned(),
            ..Default::default()
        })
        .unwrap();
        let mut ids = watcher.poller.tracked_aid_ids();
        ids.sort_by_key(|id| id.to_string());
        let mut expected = vec![tracked.id.clone(), subscribed.id.clone()];
        expected.sort_by_key(|id| id.to_string());
        assert_eq!(ids, expected);
        assert!(watcher.poller.is_subscribed(&subscribed.id));
        assert!(!watcher.poller.is_subscribed(&tracked.id));
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
            serde_json::json!({ "protocol": "2.0", "cesr_genus": "2.0" })
        );
    }

    #[actix_web::test]
    async fn info_reports_the_keri_version_the_watcher_writes() {
        let db = Builder::new().prefix("watcher-db").tempdir().unwrap();
        let watcher = Watcher::setup_with_redb(WatcherConfig {
            public_address: Url::parse("http://some/dummy/url").unwrap(),
            db_path: db.path().to_owned(),
            keri_version: keri_core::event_message::keri_version::KeriVersion::V1_0,
            ..Default::default()
        })
        .unwrap();
        let response = http_handlers::info(web::Data::new(Arc::new(watcher))).await;
        let info: serde_json::Value =
            serde_json::from_slice(&to_bytes(response.into_body()).await.unwrap()).unwrap();
        assert_eq!(
            info["keri"],
            serde_json::json!({ "protocol": "1.0", "cesr_genus": "2.0" })
        );
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

/// A query the watcher cannot answer for a reason on the asker's side is
/// refused with a 4xx status, so a client can tell it from a watcher
/// failure. The body still carries the error for the client to decode.
mod query_status {
    use std::sync::{Arc, Mutex};

    use actix_web::{http::StatusCode, web, ResponseError};
    use keri_core::{
        actor::{
            error::ActorError,
            prelude::{HashFunctionCode, SerializationFormats},
            simple_controller::SimpleController,
        },
        database::redb::RedbDatabase,
        event_message::{
            keri_version::KeriVersion,
            signed_event_message::{Message, Op},
        },
        oobi::Role,
        oobi_manager::RedbOobiStorage,
        prefix::{BasicPrefix, IdentifierPrefix, IndexedSignature, SelfSigningPrefix},
        processor::escrow::EscrowConfig,
        query::query_event::{
            OobiQueryArgs, QueryEvent, QueryRoute, SignedKelQuery, SignedQueryMessage,
        },
        signer::{CryptoBox, KeyManager, Signer},
    };
    use tempfile::{Builder, TempDir};
    use url::Url;

    use crate::{watcher_listener::http_handlers, Watcher, WatcherConfig};

    struct Fixture {
        watcher: Arc<Watcher<RedbOobiStorage>>,
        asker: SimpleController<CryptoBox, RedbDatabase, RedbOobiStorage>,
        _dirs: Vec<TempDir>,
    }

    fn setup() -> Fixture {
        let asker_db_dir = Builder::new().prefix("qry-status-asker").tempdir().unwrap();
        let asker_db = Arc::new(RedbDatabase::new(&asker_db_dir.path().join("events")).unwrap());
        let keys = Arc::new(Mutex::new(CryptoBox::new().unwrap()));
        let mut asker = SimpleController::new(asker_db, keys, EscrowConfig::default()).unwrap();
        let asker_icp = asker.incept(None, None, None).unwrap().encode().unwrap();

        let root = Builder::new().prefix("qry-status-watcher").tempdir().unwrap();
        let watcher = Watcher::setup_with_redb(WatcherConfig {
            public_address: Url::parse("http://some/dummy/url").unwrap(),
            db_path: root.path().to_owned(),
            ..Default::default()
        })
        .unwrap();
        watcher.parse_and_process_notices(&asker_icp).unwrap();

        Fixture {
            watcher: Arc::new(watcher),
            asker,
            _dirs: vec![asker_db_dir, root],
        }
    }

    async fn grant_watcher_role(fx: &Fixture) {
        let end_role = fx
            .asker
            .add_watcher(&IdentifierPrefix::Basic(fx.watcher.prefix()))
            .unwrap();
        fx.watcher.watcher_data.process_op(end_role).await.unwrap();
    }

    /// Asks the watcher, over its HTTP handler, for the key state of an
    /// identifier it has never heard of.
    async fn ask_about_unknown(fx: &Fixture) -> (StatusCode, ActorError) {
        let unknown = IdentifierPrefix::Basic(BasicPrefix::Ed25519(Signer::new().public_key()));
        ask(fx, fx.asker.query_ksn(&unknown).unwrap()).await
    }

    /// Sends `query` to the watcher's HTTP handler, which must refuse it.
    async fn ask(fx: &Fixture, query: Op) -> (StatusCode, ActorError) {
        let body = Message::Op(query).to_cesr().unwrap();
        let refused = http_handlers::process_query(
            web::Bytes::from(body),
            web::Data::new(fx.watcher.clone()),
        )
        .await
        .unwrap_err();
        let response = refused.error_response();
        let body = actix_web::body::to_bytes(response.into_body()).await.unwrap();
        (refused.status_code(), serde_json::from_slice(&body).unwrap())
    }

    #[actix_web::test]
    async fn an_identifier_the_watcher_has_no_log_for_is_not_found() {
        let fx = setup();
        grant_watcher_role(&fx).await;

        let (status, err) = ask_about_unknown(&fx).await;

        assert_eq!(status, StatusCode::NOT_FOUND);
        assert!(
            matches!(err, ActorError::NoIdentState { .. }),
            "expected NoIdentState, got {err:?}"
        );
    }

    /// The KERI specification's `/oobi` query is read, but a watcher does
    /// not answer it: the asker learns so with a 400, not a server error.
    #[actix_web::test]
    async fn an_oobi_query_is_not_served() {
        let fx = setup();
        grant_watcher_role(&fx).await;
        let qry = QueryEvent::new_query(
            QueryRoute::Oobi {
                reply_route: "/oobi/process".into(),
                args: OobiQueryArgs {
                    i: fx.asker.prefix().clone(),
                    role: Role::Witness,
                },
            },
            fx.asker.prefix(),
            KeriVersion::V2_0,
            SerializationFormats::JSON,
            HashFunctionCode::Blake3_256,
        );
        let sig = fx
            .asker
            .key_manager
            .lock()
            .unwrap()
            .sign(&qry.encode().unwrap())
            .unwrap();
        let query = Op::Query(SignedQueryMessage::KelQuery(SignedKelQuery::new_trans(
            qry,
            fx.asker.prefix().clone(),
            vec![IndexedSignature::new_both_same(
                SelfSigningPrefix::Ed25519Sha512(sig),
                0,
            )],
        )));

        let (status, err) = ask(&fx, query).await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(
            matches!(err, ActorError::UnsupportedQuery(ref route) if route == "/oobi"),
            "expected UnsupportedQuery, got {err:?}"
        );
    }

    #[actix_web::test]
    async fn a_signer_without_a_watcher_role_is_forbidden() {
        let fx = setup();

        let (status, err) = ask_about_unknown(&fx).await;

        assert_eq!(status, StatusCode::FORBIDDEN);
        assert!(
            matches!(err, ActorError::MissingRole { .. }),
            "expected MissingRole, got {err:?}"
        );
    }
}

/// A watcher serves the locations it learned of other endpoints as those
/// endpoints signed them, so a client can check them against the endpoint
/// itself and not against the watcher.
mod forwarded_locations {
    use std::sync::Arc;

    use actix_web::{body::to_bytes, http::StatusCode, web};
    use keri_core::{
        actor::{
            parse_event_stream,
            prelude::{HashFunctionCode, SerializationFormats},
        },
        event_message::{
            keri_version::KeriVersion,
            signature::{couplets_verify, Nontransferable, Signature},
            signed_event_message::{Message, Op},
        },
        oobi::{LocationScheme, Role, Scheme},
        oobi_manager::RedbOobiStorage,
        prefix::{BasicPrefix, IdentifierPrefix, SelfSigningPrefix},
        query::reply_event::{ReplyEvent, ReplyRoute, SignedReply},
        signer::Signer,
    };
    use tempfile::{Builder, TempDir};
    use url::Url;

    use crate::{watcher_listener::http_handlers, Watcher, WatcherConfig};

    struct Fixture {
        _dir: TempDir,
        watcher: Arc<Watcher<RedbOobiStorage>>,
        witness: IdentifierPrefix,
    }

    /// A watcher that learned a witness's location from the witness.
    fn setup() -> Fixture {
        let dir = Builder::new().prefix("watcher-fwd-loc").tempdir().unwrap();
        let watcher = Arc::new(
            Watcher::setup_with_redb(WatcherConfig {
                public_address: Url::parse("http://watcher-under-test/").unwrap(),
                db_path: dir.path().to_owned(),
                ..Default::default()
            })
            .unwrap(),
        );
        let witness_signer = Signer::new();
        let witness_key = BasicPrefix::Ed25519NT(witness_signer.public_key());
        let witness = IdentifierPrefix::Basic(witness_key.clone());
        let reply = ReplyEvent::new_reply(
            ReplyRoute::LocScheme(LocationScheme::new(
                witness.clone(),
                Scheme::Http,
                Url::parse("http://witness-under-test/").unwrap(),
            )),
            &witness,
            KeriVersion::V2_0,
            HashFunctionCode::Blake3_256,
            SerializationFormats::JSON,
        );
        let signature = witness_signer.sign(reply.encode().unwrap()).unwrap();
        watcher
            .watcher_data
            .process_reply(SignedReply::new_nontrans(
                reply,
                witness_key,
                SelfSigningPrefix::Ed25519Sha512(signature),
            ))
            .unwrap();
        Fixture {
            _dir: dir,
            watcher,
            witness,
        }
    }

    /// Every reply in `body`, checked the way a client parses it.
    fn replies(body: &[u8]) -> Vec<SignedReply> {
        parse_event_stream(body)
            .expect("a client parses what the watcher serves")
            .into_iter()
            .map(|msg| match msg {
                Message::Op(Op::Reply(rpy)) => rpy,
                other => panic!("expected a reply, got {other:?}"),
            })
            .collect()
    }

    fn assert_signed_by(rpy: &SignedReply, signer: &IdentifierPrefix) {
        assert_eq!(rpy.signature.get_signer().as_ref(), Some(signer));
        let Signature::NonTransferable(Nontransferable::Couplet(couplets)) = &rpy.signature else {
            panic!("expected a couplet, got {:?}", rpy.signature);
        };
        assert!(couplets_verify(couplets, &rpy.reply.encode().unwrap()));
    }

    #[actix_web::test]
    async fn a_witness_location_is_served_as_the_witness_signed_it() {
        let fx = setup();
        let controller = IdentifierPrefix::Basic(BasicPrefix::Ed25519(Signer::new().public_key()));
        let response = http_handlers::resolve_role(
            web::Path::from((controller, Role::Witness, fx.witness.clone())),
            web::Data::new(fx.watcher.clone()),
        )
        .await
        .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body()).await.unwrap();

        let replies = replies(&body);
        assert_eq!(replies.len(), 1);
        assert_signed_by(&replies[0], &fx.witness);
    }

    #[actix_web::test]
    async fn a_location_asked_for_by_eid_is_served_as_its_endpoint_signed_it() {
        let fx = setup();
        let response = http_handlers::resolve_location(
            web::Path::from(fx.witness.clone()),
            web::Data::new(fx.watcher.clone()),
        )
        .await
        .unwrap();
        let body = to_bytes(response.into_body()).await.unwrap();

        let replies = replies(&body);
        assert_eq!(replies.len(), 1);
        assert_signed_by(&replies[0], &fx.witness);
    }

    #[actix_web::test]
    async fn the_watcher_location_is_signed_by_the_watcher() {
        let fx = setup();
        let own = IdentifierPrefix::Basic(fx.watcher.prefix());
        let response = http_handlers::resolve_location(
            web::Path::from(own.clone()),
            web::Data::new(fx.watcher.clone()),
        )
        .await
        .unwrap();
        let body = to_bytes(response.into_body()).await.unwrap();

        let replies = replies(&body);
        assert_eq!(replies.len(), 1);
        assert_signed_by(&replies[0], &own);
    }
}
