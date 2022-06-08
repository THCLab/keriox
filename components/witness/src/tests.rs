use std::sync::{Arc, Mutex};

use controller::controller::Controller;
use keri::{
    database::sled::SledEventDatabase,
    derivation::{self_addressing::SelfAddressing, self_signing::SelfSigning},
    error::Error,
    event::SerializationFormats,
    event_message::signed_event_message::Message,
    prefix::{AttachedSignaturePrefix, IdentifierPrefix},
    query::query_event::{QueryArgsMbx, QueryEvent, QueryRoute, QueryTopics, SignedQuery},
    signer::Signer,
};

use crate::witness::Witness;

#[test]
fn test_not_fully_witnessed() -> Result<(), Error> {
    use controller::controller::Controller;
    use keri::event::sections::threshold::SignatureThreshold;
    use std::sync::Mutex;
    use tempfile::Builder;

    let signer_arc = Arc::new(Signer::new());
    let signer_arc2 = Arc::new(Signer::new());

    let mut controller = {
        // Create test db and event processor.
        let root = Builder::new().prefix("test-db").tempdir().unwrap();
        std::fs::create_dir_all(root.path()).unwrap();
        let db_controller = Arc::new(SledEventDatabase::new(root.path()).unwrap());

        let key_manager = {
            use keri::signer::CryptoBox;
            Arc::new(Mutex::new(CryptoBox::new()?))
        };
        Controller::new(Arc::clone(&db_controller), key_manager.clone())?
    };

    assert_eq!(controller.get_state()?, None);

    let first_witness = {
        let root_witness = Builder::new().prefix("test-db1").tempdir().unwrap();
        std::fs::create_dir_all(root_witness.path()).unwrap();
        Witness::new(root_witness.path(), signer_arc.clone().public_key())?
    };

    let second_witness = {
        let root_witness = Builder::new().prefix("test-db1").tempdir().unwrap();
        std::fs::create_dir_all(root_witness.path()).unwrap();
        Witness::new(root_witness.path(), signer_arc2.clone().public_key())?
    };

    // Get inception event.
    let inception_event = controller.incept(
        Some(vec![
            first_witness.prefix.clone(),
            second_witness.prefix.clone(),
        ]),
        Some(SignatureThreshold::Simple(2)),
    )?;

    // Shouldn't be accepted in controllers kel, because of missing witness receipts
    assert_eq!(controller.get_state()?, None);

    let receipts = [&first_witness, &second_witness]
        .iter()
        .flat_map(|w| {
            w.process(&vec![Message::Event(inception_event.clone())])
                .unwrap();
            w.respond(signer_arc.clone()).unwrap();
            w.storage
                .db
                .get_mailbox_receipts(controller.prefix())
                .into_iter()
                .flatten()
        })
        .map(Message::NontransferableRct)
        .collect::<Vec<_>>();

    assert_eq!(receipts.len(), 2);

    // Witness updates state of identifier even if it hasn't all receipts
    assert_eq!(
        first_witness
            .get_state_for_prefix(&controller.prefix())?
            .unwrap()
            .sn,
        0
    );
    assert_eq!(
        second_witness
            .get_state_for_prefix(&controller.prefix())?
            .unwrap()
            .sn,
        0
    );

    // process first receipt
    controller.process(&[receipts[0].clone()]).unwrap();

    // Still not fully witnessed
    assert_eq!(controller.get_state()?, None);

    // process second receipt
    controller.process(&[receipts[1].clone()]).unwrap();

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
    first_witness.process(receipts.as_slice())?;
    second_witness.process(receipts.as_slice())?;

    assert_eq!(
        first_witness
            .get_state_for_prefix(&controller.prefix())?
            .map(|state| state.sn),
        Some(0)
    );
    assert_eq!(
        second_witness
            .get_state_for_prefix(&controller.prefix())?
            .map(|state| state.sn),
        Some(0)
    );

    let not_fully_witnessed_events = first_witness
        .storage
        .db
        .get_partially_witnessed_events(&controller.prefix());
    assert!(not_fully_witnessed_events.is_none());
    let not_fully_witnessed_events = second_witness
        .storage
        .db
        .get_partially_witnessed_events(&controller.prefix());
    assert!(not_fully_witnessed_events.is_none());

    let rotation_event = controller.rotate(
        None,
        Some(&[second_witness.prefix.clone()]),
        Some(SignatureThreshold::Simple(1)),
    );
    // Rotation not yet accepted by controller, missing receipts
    assert_eq!(controller.get_state()?.unwrap().sn, 0);
    first_witness.process(&[Message::Event(rotation_event?)])?;
    first_witness.respond(signer_arc.clone())?;
    let first_receipt = first_witness
        .storage
        .db
        .get_mailbox_receipts(controller.prefix())
        .unwrap()
        .map(Message::NontransferableRct)
        .collect::<Vec<_>>();

    // Receipt accepted by witness, because his the only designated witness
    assert_eq!(
        first_witness
            .get_state_for_prefix(&controller.prefix())?
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
    use tempfile::Builder;

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

    // Create test db and event processor.
    let root = Builder::new().prefix("test-db").tempdir().unwrap();
    let alice_db = Arc::new(SledEventDatabase::new(root.path()).unwrap());
    let root = Builder::new().prefix("test-db").tempdir().unwrap();
    let bob_db = Arc::new(SledEventDatabase::new(root.path()).unwrap());

    let witness_root = Builder::new().prefix("test-db").tempdir().unwrap();
    let signer = Signer::new();
    let signer_arc = Arc::new(signer);
    let witness = Witness::new(witness_root.path(), signer_arc.public_key())?;

    let alice_key_manager = Arc::new(Mutex::new({
        use keri::signer::CryptoBox;
        CryptoBox::new()?
    }));

    // Init alice.
    let mut alice = Controller::new(Arc::clone(&alice_db), Arc::clone(&alice_key_manager))?;

    let bob_key_manager = Arc::new(Mutex::new({
        use keri::signer::CryptoBox;
        CryptoBox::new()?
    }));

    // Init bob.
    let mut bob = Controller::new(Arc::clone(&bob_db), Arc::clone(&bob_key_manager))?;

    let bob_icp = bob.incept(None, None).unwrap();
    // bob.rotate().unwrap();

    let bob_pref = bob.prefix();

    let alice_icp = alice.incept(Some(vec![witness.prefix.clone()]), None)?;
    // send alices icp to witness
    witness.process(&[Message::Event(alice_icp)])?;
    witness.respond(signer_arc.clone())?;
    // send receipts to alice
    let receipt_to_alice = witness
        .storage
        .db
        .get_mailbox_receipts(alice.prefix())
        .unwrap()
        .map(|e| Message::NontransferableRct(e))
        .collect::<Vec<_>>();
    alice.process(&receipt_to_alice)?;

    // send bobs icp to witness to have his keys
    witness.process(&[Message::Event(bob_icp)])?;
    let _receipts = witness.respond(signer_arc.clone());

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
    let query_message = Message::Query(SignedQuery::new(qry, bob_pref.to_owned(), vec![signature]));

    witness.process(&vec![query_message])?;

    let response = witness.respond(signer_arc.clone())?;
    // assert_eq!(response.len(), 1);
    match &response[0] {
        Message::Reply(rpy) => {
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
    let query_message = Message::Query(SignedQuery::new(qry, bob_pref.to_owned(), vec![signature]));

    witness.process(&vec![query_message])?;

    let response = witness.respond(signer_arc)?;

    let alice_kel = alice
        .storage
        .get_kel_messages_with_receipts(alice.prefix())?;
    assert_eq!(response, alice_kel.unwrap());

    Ok(())
}

#[test]
pub fn test_key_state_notice() -> Result<(), Error> {
    use keri::{
        processor::{notification::Notification, EventProcessor},
        query::QueryError,
        signer::{CryptoBox, Signer},
    };
    use tempfile::Builder;

    let signer = Signer::new();
    let signer_arc = Arc::new(signer);
    let witness = {
        let witness_root = Builder::new().prefix("test-db").tempdir().unwrap();
        let path = witness_root.path();
        std::fs::create_dir_all(path).unwrap();
        Witness::new(path, signer_arc.clone().public_key())?
    };

    // Init bob.
    let mut bob = {
        // Create test db and event processor.
        let root = Builder::new().prefix("test-db").tempdir().unwrap();
        std::fs::create_dir_all(root.path()).unwrap();
        let db = Arc::new(SledEventDatabase::new(root.path()).unwrap());

        let bob_key_manager = Arc::new(Mutex::new(CryptoBox::new()?));
        Controller::new(Arc::clone(&db), Arc::clone(&bob_key_manager))?
    };

    let alice_processor = {
        let root = Builder::new().prefix("test-db2").tempdir().unwrap();
        std::fs::create_dir_all(root.path()).unwrap();
        let db2 = Arc::new(SledEventDatabase::new(root.path()).unwrap());
        EventProcessor::new(db2.clone())
    };

    let bob_icp = bob
        .incept(Some(vec![witness.prefix.clone()]), None)
        .unwrap();
    // bob.rotate().unwrap();

    let bob_pref = bob.prefix().clone();

    // send bobs icp to witness to have his keys
    witness.process(&[Message::Event(bob_icp.clone())])?;

    // construct bobs ksn msg in rpy made by witness
    let signed_rpy = witness.get_ksn_for_prefix(&bob_pref, signer_arc.clone())?;

    // Process reply message before having any bob's events in db.
    let res = alice_processor.process(Message::Reply(signed_rpy.clone()));
    assert!(matches!(res, Ok(Notification::KsnOutOfOrder(_))));
    alice_processor.process(Message::Event(bob_icp))?;

    // rotate bob's keys. Let alice process his rotation. She will have most recent bob's event.
    let bob_rot = bob.rotate(None, None, None)?;
    witness.process(&[Message::Event(bob_rot.clone())])?;
    alice_processor.process(Message::Event(bob_rot.clone()))?;

    // try to process old reply message
    let res = alice_processor.process(Message::Reply(signed_rpy.clone()));
    assert!(matches!(res, Err(Error::QueryError(QueryError::StaleKsn))));

    // now create new reply event by witness and process it by alice.
    let new_reply = witness.get_ksn_for_prefix(&bob_pref, signer_arc.clone())?;
    let res = alice_processor.process(Message::Reply(new_reply.clone()));
    assert!(res.is_ok());

    let new_bob_rot = bob.rotate(None, None, None)?;
    witness.process(&[Message::Event(new_bob_rot.clone())])?;
    // Create transferable reply by bob and process it by alice.
    let trans_rpy = witness.get_ksn_for_prefix(&bob_pref, signer_arc)?;

    let res = alice_processor.process(Message::Reply(trans_rpy.clone()));
    assert!(matches!(res, Ok(Notification::KsnOutOfOrder(_))));

    // Now update bob's state in alice's db to most recent.
    alice_processor.process(Message::Event(new_bob_rot))?;
    let res = alice_processor.process(Message::Reply(trans_rpy.clone()));
    assert_eq!(res?, Notification::ReplyUpdated);

    Ok(())
}

#[test]
fn test_mbx() {
    use controller::controller::Controller;
    use keri::event::sections::threshold::SignatureThreshold;
    use keri::signer::CryptoBox;
    use std::sync::Mutex;

    let signer = Arc::new(Signer::new());

    let mut controllers = (0..2)
        .map(|i| {
            let root = tempfile::Builder::new()
                .prefix(&format!("test-ctrl-{i}"))
                .tempdir()
                .unwrap();
            std::fs::create_dir_all(root.path()).unwrap();
            let db_controller = Arc::new(SledEventDatabase::new(root.path()).unwrap());
            let key_manager = Arc::new(Mutex::new(CryptoBox::new().unwrap()));
            Controller::new(Arc::clone(&db_controller), key_manager.clone()).unwrap()
        })
        .collect::<Vec<_>>();

    let witness = {
        let root = tempfile::Builder::new()
            .prefix("test-witness")
            .tempdir()
            .unwrap();
        std::fs::create_dir_all(root.path()).unwrap();
        Witness::new(root.path(), signer.clone().public_key()).unwrap()
    };

    // create inception events
    for controller in &mut controllers {
        let incept_event = controller
            .incept(
                Some(vec![witness.prefix.clone()]),
                Some(SignatureThreshold::Simple(1)),
            )
            .unwrap();

        // send to witness
        witness
            .process(&vec![Message::Event(incept_event.clone())])
            .unwrap();
        witness.respond(signer.clone()).unwrap();
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

        use keri::signer::KeyManager;
        let signature = controller
            .key_manager()
            .lock()
            .unwrap()
            .sign(&qry_msg.serialize().unwrap())
            .unwrap();

        let signatures = vec![AttachedSignaturePrefix::new(
            SelfSigning::Ed25519Sha512,
            signature,
            0,
        )];

        let mbx_msg = Message::Query(SignedQuery::new(
            qry_msg,
            controller.prefix().clone().clone(),
            signatures,
        ));

        witness.process(&[mbx_msg]).unwrap();
        let receipts = &witness.respond(signer.clone()).unwrap();

        assert_eq!(receipts.len(), 1);
        let receipt = receipts[0].clone();

        let receipt = if let Message::NontransferableRct(receipt) = receipt {
            receipt
        } else {
            panic!("didn't receive a receipt")
        };

        assert_eq!(receipt.body.event.sn, 0);
        assert_eq!(receipt.body.event.prefix, controller.prefix().clone());
    }
}
