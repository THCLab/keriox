use std::sync::{Arc, Mutex};

use keri::{
    database::sled::SledEventDatabase,
    derivation::{self_addressing::SelfAddressing, self_signing::SelfSigning},
    error::Error,
    event::SerializationFormats,
    event_message::signed_event_message::{Message, Notice, Op},
    prefix::{AttachedSignaturePrefix, IdentifierPrefix},
    processor::{basic_processor::BasicProcessor, event_storage::EventStorage, Processor},
    query::query_event::{QueryArgsMbx, QueryEvent, QueryRoute, QueryTopics, SignedQuery},
    signer::{KeyManager, Signer},
};

use crate::{tests::controller_helper::Controller, witness::Witness};

mod controller_helper {
    use std::{
        path::Path,
        sync::{Arc, Mutex},
    };

    use keri::{
        actor::process_event,
        controller::event_generator,
        database::sled::SledEventDatabase,
        derivation::{basic::Basic, self_signing::SelfSigning},
        error::Error,
        event_message::signed_event_message::{Message, SignedEventMessage},
        event_parsing::{message::key_event_message, EventType},
        oobi::OobiManager,
        prefix::{AttachedSignaturePrefix, BasicPrefix, IdentifierPrefix},
        processor::{basic_processor::BasicProcessor, event_storage::EventStorage},
        signer::KeyManager,
        state::IdentifierState,
    };

    /// Helper struct for events generation, signing and processing.
    pub struct Controller<K: KeyManager + 'static> {
        prefix: IdentifierPrefix,
        pub key_manager: Arc<Mutex<K>>,
        processor: BasicProcessor,
        oobi_manager: OobiManager,
        pub storage: EventStorage,
    }

    impl<K: KeyManager> Controller<K> {
        // incept a state and keys
        pub fn new(
            db: Arc<SledEventDatabase>,
            key_manager: Arc<Mutex<K>>,
            oobi_db_path: &Path,
        ) -> Result<Controller<K>, Error> {
            let processor = BasicProcessor::new(db.clone());

            Ok(Controller {
                prefix: IdentifierPrefix::default(),
                key_manager,
                oobi_manager: OobiManager::new(oobi_db_path),
                processor,
                storage: EventStorage::new(db),
            })
        }

        /// Getter of the instance prefix
        ///
        pub fn prefix(&self) -> &IdentifierPrefix {
            &self.prefix
        }

        pub fn incept(
            &mut self,
            initial_witness: Option<Vec<BasicPrefix>>,
            witness_threshold: Option<u64>,
        ) -> Result<SignedEventMessage, Error> {
            let km = self.key_manager.lock().map_err(|_| Error::MutexPoisoned)?;
            let icp = event_generator::incept(
                vec![Basic::Ed25519.derive(km.public_key())],
                vec![Basic::Ed25519.derive(km.next_public_key())],
                initial_witness.unwrap_or_default(),
                witness_threshold.unwrap_or(0),
            )
            .unwrap();
            let signature = km.sign(icp.as_bytes())?;
            let (_, key_event) = key_event_message(icp.as_bytes()).unwrap();
            let signed = if let EventType::KeyEvent(icp) = key_event {
                icp.sign(
                    vec![AttachedSignaturePrefix::new(
                        SelfSigning::Ed25519Sha512,
                        signature,
                        0,
                    )],
                    None,
                    None,
                )
            } else {
                unreachable!()
            };

            self.processor.process(&Message::Event(signed.clone()))?;

            self.prefix = signed.event_message.event.get_prefix();
            // No need to generate receipt

            Ok(signed)
        }

        pub fn rotate(
            &mut self,
            witness_to_add: Option<&[BasicPrefix]>,
            witness_to_remove: Option<&[BasicPrefix]>,
            witness_threshold: Option<u64>,
        ) -> Result<SignedEventMessage, Error> {
            let rot = self.make_rotation(witness_to_add, witness_to_remove, witness_threshold)?;
            let km = self.key_manager.lock().map_err(|_| Error::MutexPoisoned)?;
            let signature = km.sign(rot.as_bytes())?;

            let (_, key_event) = key_event_message(rot.as_bytes()).unwrap();

            let signed = if let EventType::KeyEvent(rot) = key_event {
                rot.sign(
                    vec![AttachedSignaturePrefix::new(
                        SelfSigning::Ed25519Sha512,
                        signature,
                        0,
                    )],
                    None,
                    None,
                )
            } else {
                unreachable!()
            };

            self.processor.process(&Message::Event(signed.clone()))?;

            Ok(signed)
        }

        fn make_rotation(
            &self,
            witness_to_add: Option<&[BasicPrefix]>,
            witness_to_remove: Option<&[BasicPrefix]>,
            witness_threshold: Option<u64>,
        ) -> Result<String, Error> {
            let mut km = self.key_manager.lock().map_err(|_| Error::MutexPoisoned)?;
            km.rotate()?;
            let state = self
                .storage
                .get_state(&self.prefix)?
                .ok_or_else(|| Error::SemanticError("There is no state".into()))?;

            Ok(event_generator::rotate(
                state,
                vec![Basic::Ed25519.derive(km.public_key())],
                vec![Basic::Ed25519.derive(km.next_public_key())],
                witness_to_add.unwrap_or_default().to_vec(),
                witness_to_remove.unwrap_or_default().into(),
                witness_threshold.unwrap_or(0),
            )
            .unwrap())
        }

        pub fn process(&self, msg: &[Message]) -> Result<(), Error> {
            let (_process_ok, _process_failed): (Vec<_>, Vec<_>) = msg
                .iter()
                .map(|message| {
                    process_event(
                        message.clone(),
                        &self.oobi_manager,
                        &self.processor,
                        &self.storage,
                    )
                })
                .partition(Result::is_ok);

            Ok(())
        }

        pub fn get_state(&self) -> Result<Option<IdentifierState>, Error> {
            self.storage.get_state(&self.prefix)
        }
    }
}

#[test]
fn test_not_fully_witnessed() -> Result<(), Error> {
    use std::sync::Mutex;

    use controller::controller::Controller;
    use keri::event::sections::threshold::SignatureThreshold;
    use tempfile::Builder;

    let seed1 = "ArwXoACJgOleVZ2PY7kXn7rA0II0mHYDhc6WrBH8fDAc";
    let seed2 = "A6zz7M08-HQSFq92sJ8KJOT2cZ47x7pXFQLPB0pckB3Q";

    let mut controller = {
        // Create test db and event processor.
        let root = Builder::new().prefix("test-db").tempdir().unwrap();
        std::fs::create_dir_all(root.path()).unwrap();
        let db_controller = Arc::new(SledEventDatabase::new(root.path()).unwrap());

        let oobi_root = Builder::new().prefix("test-db").tempdir().unwrap();

        let key_manager = {
            use keri::signer::CryptoBox;
            Arc::new(Mutex::new(CryptoBox::new()?))
        };
        Controller::new(
            Arc::clone(&db_controller),
            key_manager.clone(),
            oobi_root.path(),
        )?
    };

    assert_eq!(controller.get_state()?, None);

    let first_witness = {
        let root_witness = Builder::new().prefix("test-db1").tempdir().unwrap();
        let oobi_root = Builder::new().prefix("test-db_oobi").tempdir().unwrap();
        std::fs::create_dir_all(root_witness.path()).unwrap();
        Witness::setup(
            url::Url::parse("http://some/url").unwrap(),
            root_witness.path(),
            &oobi_root.path(),
            Some(seed1.into()),
        )?
    };

    let second_witness = {
        let root_witness = Builder::new().prefix("test-db1").tempdir().unwrap();
        let oobi_root = Builder::new().prefix("test-db_oobi").tempdir().unwrap();
        std::fs::create_dir_all(root_witness.path()).unwrap();
        Witness::setup(
            url::Url::parse("http://some/url").unwrap(),
            root_witness.path(),
            &oobi_root.path(),
            Some(seed2.into()),
        )?
    };

    // Get inception event.
    let inception_event = controller.incept(
        Some(vec![
            first_witness.prefix.clone(),
            second_witness.prefix.clone(),
        ]),
        Some(2),
    )?;

    // Shouldn't be accepted in controllers kel, because of missing witness receipts
    assert_eq!(controller.get_state()?, None);

    let receipts = [&first_witness, &second_witness]
        .iter()
        .flat_map(|w| {
            w.process_notice(Notice::Event(inception_event.clone()))
                .unwrap();
            w.event_storage
                .db
                .get_mailbox_receipts(controller.prefix())
                .into_iter()
                .flatten()
        })
        .map(Notice::NontransferableRct)
        .collect::<Vec<_>>();

    assert_eq!(receipts.len(), 2);

    // Witness updates state of identifier even if it hasn't all receipts
    assert_eq!(
        first_witness
            .event_storage
            .get_state(&controller.prefix())?
            .unwrap()
            .sn,
        0
    );
    assert_eq!(
        second_witness
            .event_storage
            .get_state(&controller.prefix())?
            .unwrap()
            .sn,
        0
    );

    // process first receipt
    controller
        .process(&[Message::Notice(receipts[0].clone())])
        .unwrap();

    // Still not fully witnessed
    assert_eq!(controller.get_state()?, None);

    // process second receipt
    controller
        .process(&[Message::Notice(receipts[1].clone())])
        .unwrap();

    // Now fully witnessed, should be in kel
    assert_eq!(controller.get_state()?.map(|state| state.sn), Some(0));
    assert_eq!(
        controller
            .get_state()?
            .map(|state| state.witness_config.witnesses),
        Some(vec![
            first_witness.prefix.clone(),
            second_witness.prefix.clone()
        ])
    );

    // Process receipts by witnesses.
    receipts
        .clone()
        .into_iter()
        .map(|rct| first_witness.process_notice(rct))
        .collect::<Result<Vec<_>, _>>()?;
    receipts
        .into_iter()
        .map(|rct| second_witness.process_notice(rct))
        .collect::<Result<Vec<_>, _>>()?;

    assert_eq!(
        first_witness
            .event_storage
            .get_state(&controller.prefix())?
            .map(|state| state.sn),
        Some(0)
    );
    assert_eq!(
        second_witness
            .event_storage
            .get_state(&controller.prefix())?
            .map(|state| state.sn),
        Some(0)
    );

    let not_fully_witnessed_events = first_witness
        .event_storage
        .db
        .get_partially_witnessed_events(&controller.prefix());
    assert!(not_fully_witnessed_events.is_none());
    let not_fully_witnessed_events = second_witness
        .event_storage
        .db
        .get_partially_witnessed_events(&controller.prefix());
    assert!(not_fully_witnessed_events.is_none());

    let rotation_event = controller.rotate(None, Some(&[second_witness.prefix.clone()]), Some(1));
    // Rotation not yet accepted by controller, missing receipts
    assert_eq!(controller.get_state()?.unwrap().sn, 0);
    first_witness.process_notice(Notice::Event(rotation_event?))?;
    // first_witness.respond(signer_arc.clone())?;
    let first_receipt = first_witness
        .event_storage
        .db
        .get_mailbox_receipts(controller.prefix())
        .unwrap()
        .map(Notice::NontransferableRct)
        .map(Message::Notice)
        .collect::<Vec<_>>();

    // Receipt accepted by witness, because his the only designated witness
    assert_eq!(
        first_witness
            .event_storage
            .get_state(&controller.prefix())?
            .unwrap()
            .sn,
        1
    );

    // process receipt by controller
    controller.process(&first_receipt)?;
    assert_eq!(controller.get_state()?.unwrap().sn, 1);

    assert_eq!(
        controller
            .get_state()?
            .map(|state| state.witness_config.witnesses),
        Some(vec![first_witness.prefix.clone(),])
    );

    Ok(())
}

#[test]
fn test_qry_rpy() -> Result<(), Error> {
    use keri::{
        derivation::{self_addressing::SelfAddressing, self_signing::SelfSigning},
        event::SerializationFormats,
        prefix::AttachedSignaturePrefix,
        query::{
            query_event::{QueryArgs, QueryEvent, QueryRoute, SignedQuery},
            reply_event::ReplyRoute,
        },
        signer::{KeyManager, Signer},
    };
    use tempfile::Builder;

    // Create test db and event processor.
    let root = Builder::new().prefix("test-alice-db").tempdir().unwrap();
    let alice_oobi_root = Builder::new().prefix("test-db").tempdir().unwrap();
    let alice_db = Arc::new(SledEventDatabase::new(root.path()).unwrap());
    let root = Builder::new().prefix("test_bob-db").tempdir().unwrap();
    let bob_oobi_root = Builder::new().prefix("test-db").tempdir().unwrap();
    let bob_db = Arc::new(SledEventDatabase::new(root.path()).unwrap());

    let witness_root = Builder::new().prefix("test-db").tempdir().unwrap();
    let witness_oobi_root = Builder::new().prefix("test-db").tempdir().unwrap();
    let signer = Signer::new();
    let signer_arc = Arc::new(signer);
    let witness = Witness::new(signer_arc, witness_root.path(), witness_oobi_root.path())?;

    let alice_key_manager = Arc::new(Mutex::new({
        use keri::signer::CryptoBox;
        CryptoBox::new()?
    }));

    // Init alice.
    let mut alice = Controller::new(
        Arc::clone(&alice_db),
        Arc::clone(&alice_key_manager),
        alice_oobi_root.path(),
    )?;

    let bob_key_manager = Arc::new(Mutex::new({
        use keri::signer::CryptoBox;
        CryptoBox::new()?
    }));

    // Init bob.
    let mut bob = Controller::new(
        Arc::clone(&bob_db),
        Arc::clone(&bob_key_manager),
        bob_oobi_root.path(),
    )?;

    let bob_icp = bob.incept(None, None).unwrap();
    // bob.rotate(None, None, None).unwrap();

    let bob_pref = bob.prefix();

    let alice_icp = alice.incept(Some(vec![witness.prefix.clone()]), None)?;
    // send alices icp to witness
    witness.process_notice(Notice::Event(alice_icp))?;
    // send receipts to alice
    let receipt_to_alice = witness
        .event_storage
        .db
        .get_mailbox_receipts(alice.prefix())
        .unwrap()
        .map(Notice::NontransferableRct)
        .map(Message::Notice)
        .collect::<Vec<_>>();
    alice.process(&receipt_to_alice)?;

    // send bobs icp to witness to have his keys
    witness.process_notice(Notice::Event(bob_icp))?;

    // Bob asks about alices key state
    // construct qry message to ask of alice key state message
    let query_args = QueryArgs {
        s: None,
        i: alice.prefix().clone(),
        src: None,
    };

    let qry = QueryEvent::new_query(
        QueryRoute::Ksn {
            args: query_args,
            reply_route: String::from(""),
        },
        SerializationFormats::JSON,
        &SelfAddressing::Blake3_256,
    )?;

    // sign message by bob
    let signature = AttachedSignaturePrefix::new(
        SelfSigning::Ed25519Sha512,
        Arc::clone(&bob_key_manager)
            .lock()
            .unwrap()
            .sign(&serde_json::to_vec(&qry).unwrap())?,
        0,
    );
    // Qry message signed by Bob
    let query = Op::Query(SignedQuery::new(qry, bob_pref.to_owned(), vec![signature]));

    let response = witness.process_op(query)?;

    // assert_eq!(response.len(), 1);
    match &response[0] {
        Message::Op(Op::Reply(rpy)) => {
            if let ReplyRoute::Ksn(_id, ksn) = rpy.reply.get_route() {
                assert_eq!(&ksn.state, &alice.get_state().unwrap().unwrap())
            }
        }
        _ => unreachable!(),
    }

    // Bob asks about alices kel
    // construct qry message to ask of alice kel
    let query_args = QueryArgs {
        s: None,
        i: alice.prefix().clone(),
        src: None,
    };
    let qry = QueryEvent::new_query(
        QueryRoute::Log {
            args: query_args,
            reply_route: String::from(""),
        },
        SerializationFormats::JSON,
        &SelfAddressing::Blake3_256,
    )?;

    // sign message by bob
    let signature = AttachedSignaturePrefix::new(
        SelfSigning::Ed25519Sha512,
        Arc::clone(&bob_key_manager)
            .lock()
            .unwrap()
            .sign(&serde_json::to_vec(&qry).unwrap())?,
        0,
    );
    // Qry message signed by Bob
    let query = Op::Query(SignedQuery::new(qry, bob_pref.to_owned(), vec![signature]));

    let response = witness.process_op(query)?;

    let alice_kel = alice
        .storage
        .get_kel_messages_with_receipts(alice.prefix())?
        .into_iter()
        .flatten()
        .map(Message::Notice)
        .collect::<Vec<_>>();
    assert_eq!(response, alice_kel);

    Ok(())
}

#[test]
pub fn test_key_state_notice() -> Result<(), Error> {
    use keri::{
        query::QueryError,
        signer::{CryptoBox, Signer},
    };
    use tempfile::Builder;

    let signer = Signer::new();
    let signer_arc = Arc::new(signer);
    let witness = {
        let witness_root = Builder::new().prefix("test-db").tempdir().unwrap();
        let witness_root_oobi = Builder::new().prefix("test-db").tempdir().unwrap();
        let path = witness_root.path();
        std::fs::create_dir_all(path).unwrap();
        Witness::new(signer_arc.clone(), path, witness_root_oobi.path())?
    };

    // Init bob.
    let mut bob = {
        // Create test db and event processor.
        let root = Builder::new().prefix("test-db").tempdir().unwrap();
        let oobi_root = Builder::new().prefix("alice-db-oobi").tempdir().unwrap();
        std::fs::create_dir_all(root.path()).unwrap();
        let db = Arc::new(SledEventDatabase::new(root.path()).unwrap());

        let bob_key_manager = Arc::new(Mutex::new(CryptoBox::new()?));
        Controller::new(
            Arc::clone(&db),
            Arc::clone(&bob_key_manager),
            oobi_root.path(),
        )?
    };

    let (alice_processor, alice_storage) = {
        let root = Builder::new().prefix("test-db2").tempdir().unwrap();
        std::fs::create_dir_all(root.path()).unwrap();
        let db = Arc::new(SledEventDatabase::new(root.path()).unwrap());
        (
            BasicProcessor::new(db.clone()),
            EventStorage::new(db.clone()),
        )
    };

    let bob_icp = bob
        .incept(Some(vec![witness.prefix.clone()]), None)
        .unwrap();
    // bob.rotate().unwrap();

    let bob_pref = bob.prefix().clone();

    // send bobs icp to witness to have his keys
    witness.process_notice(Notice::Event(bob_icp.clone()))?;

    // construct bobs ksn msg in rpy made by witness
    let signed_rpy = witness.get_signed_ksn_for_prefix(&bob_pref, signer_arc.clone())?;

    // Process reply message before having any bob's events in db.
    alice_processor.process_op_reply(&signed_rpy)?;
    let ksn_db = alice_storage.get_last_ksn_reply(
        &signed_rpy.reply.get_prefix(),
        &signed_rpy.signature.get_signer(),
    );
    assert!(matches!(ksn_db, None));
    alice_processor.process_notice(&Notice::Event(bob_icp))?;

    // rotate bob's keys. Let alice process his rotation. She will have most recent bob's event.
    let bob_rot = bob.rotate(None, None, None)?;
    witness.process_notice(Notice::Event(bob_rot.clone()))?;
    alice_processor.process_notice(&Notice::Event(bob_rot.clone()))?;

    // try to process old reply message
    let res = alice_processor.process_op_reply(&signed_rpy);
    assert!(matches!(res, Err(Error::QueryError(QueryError::StaleKsn))));

    // now create new reply event by witness and process it by alice.
    let new_reply = witness.get_signed_ksn_for_prefix(&bob_pref, signer_arc.clone())?;
    alice_processor.process_op_reply(&new_reply)?;
    let ksn_db = alice_storage.get_last_ksn_reply(
        &signed_rpy.reply.get_prefix(),
        &signed_rpy.signature.get_signer(),
    );
    assert!(matches!(ksn_db, Some(_)));

    let ksn_from_db_digest = ksn_db.unwrap().reply.get_digest();
    let processed_ksn_digest = new_reply.reply.get_digest();
    assert_eq!(ksn_from_db_digest, processed_ksn_digest);

    let new_bob_rot = bob.rotate(None, None, None)?;
    witness.process_notice(Notice::Event(new_bob_rot.clone()))?;
    // Create transferable reply by bob and process it by alice.
    let trans_rpy = witness.get_signed_ksn_for_prefix(&bob_pref, signer_arc)?;

    alice_processor.process_op_reply(&trans_rpy)?;
    // Reply was out of order so saved reply shouldn't be updated
    let ksn_db = alice_storage.get_last_ksn_reply(
        &signed_rpy.reply.get_prefix(),
        &signed_rpy.signature.get_signer(),
    );
    assert!(matches!(ksn_db, Some(_)));
    let ksn_from_db_digest = ksn_db.unwrap().reply.get_digest();
    let out_of_order_ksn_digest = trans_rpy.reply.get_digest();
    assert_ne!(ksn_from_db_digest, out_of_order_ksn_digest);
    assert_eq!(ksn_from_db_digest, processed_ksn_digest);

    // Now update bob's state in alice's db to most recent.
    alice_processor.process_notice(&Notice::Event(new_bob_rot))?;
    alice_processor.process_op_reply(&trans_rpy)?;

    // Reply should be updated
    let ksn_db = alice_storage.get_last_ksn_reply(
        &signed_rpy.reply.get_prefix(),
        &signed_rpy.signature.get_signer(),
    );
    assert!(matches!(ksn_db, Some(_)));
    let ksn_from_db_digest = ksn_db.unwrap().reply.get_digest();
    assert_eq!(ksn_from_db_digest, out_of_order_ksn_digest);

    Ok(())
}

#[test]
fn test_mbx() {
    use std::sync::Mutex;

    use controller::controller::Controller;
    use keri::{event::sections::threshold::SignatureThreshold, signer::CryptoBox};

    let signer = Arc::new(Signer::new());

    let mut controllers = (0..2)
        .map(|i| {
            let root = tempfile::Builder::new()
                .prefix(&format!("test-ctrl-{i}"))
                .tempdir()
                .unwrap();
            let oobi_root = tempfile::Builder::new()
                .prefix(&format!("test-ctrl-{i}"))
                .tempdir()
                .unwrap();
            std::fs::create_dir_all(root.path()).unwrap();
            let db_controller = Arc::new(SledEventDatabase::new(root.path()).unwrap());
            let key_manager = Arc::new(Mutex::new(CryptoBox::new().unwrap()));
            Controller::new(
                Arc::clone(&db_controller),
                key_manager.clone(),
                oobi_root.path(),
            )
            .unwrap()
        })
        .collect::<Vec<_>>();

    let witness = {
        let root = tempfile::Builder::new()
            .prefix("test-witness")
            .tempdir()
            .unwrap();
        let oobi_root = tempfile::Builder::new()
            .prefix(&format!("test-oobi"))
            .tempdir()
            .unwrap();
        std::fs::create_dir_all(root.path()).unwrap();
        Witness::new(signer, root.path(), oobi_root.path()).unwrap()
    };

    // create inception events
    for controller in &mut controllers {
        let incept_event = controller
            .incept(Some(vec![witness.prefix.clone()]), Some(1))
            .unwrap();

        // send to witness
        witness
            .process_notice(Notice::Event(incept_event.clone()))
            .unwrap();
    }

    // query witness
    for controller in controllers {
        let qry_msg = QueryEvent::new_query(
            QueryRoute::Mbx {
                args: QueryArgsMbx {
                    i: IdentifierPrefix::Basic(witness.prefix.clone()),
                    pre: controller.prefix().clone(),
                    src: IdentifierPrefix::Basic(witness.prefix.clone()),
                    topics: QueryTopics {
                        credential: 0,
                        receipt: 0,
                        replay: 0,
                        multisig: 0,
                        delegate: 0,
                    },
                },
                reply_route: "".to_string(),
            },
            SerializationFormats::JSON,
            &SelfAddressing::Blake3_256,
        )
        .unwrap();

        let signature = controller
            .key_manager
            .lock()
            .unwrap()
            .sign(&qry_msg.serialize().unwrap())
            .unwrap();

        let signatures = vec![AttachedSignaturePrefix::new(
            SelfSigning::Ed25519Sha512,
            signature,
            0,
        )];

        let mbx_msg = Op::Query(SignedQuery::new(
            qry_msg,
            controller.prefix().clone().clone(),
            signatures,
        ));

        let receipts = witness.process_op(mbx_msg).unwrap();

        assert_eq!(receipts.len(), 1);
        let receipt = receipts[0].clone();

        let receipt = if let Message::Notice(Notice::NontransferableRct(receipt)) = receipt {
            receipt
        } else {
            panic!("didn't receive a receipt")
        };

        assert_eq!(receipt.body.event.sn, 0);
        assert_eq!(receipt.body.event.prefix, controller.prefix().clone());
    }
}
