#![cfg(test)]

use std::sync::{Arc, Mutex};

use keri::{
    actor::{
        simple_controller::{PossibleResponse, SimpleController},
        SignedQueryError,
    },
    database::{escrow::EscrowDb, SledEventDatabase},
    derivation::basic::Basic,
    error::Error,
    event::sections::threshold::SignatureThreshold,
    event_message::{signed_event_message::{Message, Notice, Op}, exchange::ForwardTopic},
    keys::PublicKey,
    prefix::{BasicPrefix, IdentifierPrefix},
    processor::{basic_processor::BasicProcessor, event_storage::EventStorage, Processor},
    query::query_event::MailboxResponse,
    signer::{CryptoBox, Signer},
};
use tempfile::Builder;

use crate::witness::{Witness, WitnessError};

#[test]
fn test_not_fully_witnessed() -> Result<(), Error> {
    use std::sync::Mutex;

    use tempfile::Builder;

    let seed1 = "ArwXoACJgOleVZ2PY7kXn7rA0II0mHYDhc6WrBH8fDAc";
    let seed2 = "A6zz7M08-HQSFq92sJ8KJOT2cZ47x7pXFQLPB0pckB3Q";

    let mut controller = {
        // Create test db and event processor.
        let root = Builder::new().prefix("test-db").tempdir().unwrap();
        std::fs::create_dir_all(root.path()).unwrap();
        let db_controller = Arc::new(SledEventDatabase::new(root.path()).unwrap());

        let escrow_root = Builder::new().prefix("test-db-escrow").tempdir().unwrap();
        let escrow_db = Arc::new(EscrowDb::new(escrow_root.path()).unwrap());

        let oobi_root = Builder::new().prefix("test-db").tempdir().unwrap();

        let key_manager = {
            use keri::signer::CryptoBox;
            Arc::new(Mutex::new(CryptoBox::new()?))
        };
        SimpleController::new(
            Arc::clone(&db_controller),
            escrow_db,
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
fn test_qry_rpy() -> Result<(), WitnessError> {
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
    let alice_escrow_db = Arc::new(EscrowDb::new(root.path())?);
    let root = Builder::new().prefix("test_bob-db").tempdir().unwrap();
    let bob_oobi_root = Builder::new().prefix("test-db").tempdir().unwrap();
    let bob_db = Arc::new(SledEventDatabase::new(root.path()).unwrap());
    let bob_escrow_db = Arc::new(EscrowDb::new(root.path())?);

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
    let mut alice = SimpleController::new(
        Arc::clone(&alice_db),
        Arc::clone(&alice_escrow_db),
        Arc::clone(&alice_key_manager),
        alice_oobi_root.path(),
    )?;

    let bob_key_manager = Arc::new(Mutex::new({
        use keri::signer::CryptoBox;
        CryptoBox::new()?
    }));

    // Init bob.
    let mut bob = SimpleController::new(
        Arc::clone(&bob_db),
        Arc::clone(&bob_escrow_db),
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
    if let Some(PossibleResponse::Kel(response)) = response {
        match &response[0] {
            Message::Op(Op::Reply(rpy)) => {
                if let ReplyRoute::Ksn(_id, ksn) = rpy.reply.get_route() {
                    assert_eq!(&ksn.state, &alice.get_state().unwrap().unwrap())
                }
            }
            _ => unreachable!(),
        }
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
    assert_eq!(response, Some(PossibleResponse::Kel(alice_kel)));

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
        let bob_escrow_db = Arc::new(EscrowDb::new(root.path())?);

        let bob_key_manager = Arc::new(Mutex::new(CryptoBox::new()?));
        SimpleController::new(
            Arc::clone(&db),
            Arc::clone(&bob_escrow_db),
            Arc::clone(&bob_key_manager),
            oobi_root.path(),
        )?
    };

    let (alice_processor, alice_storage) = {
        let root = Builder::new().prefix("test-db2").tempdir().unwrap();
        std::fs::create_dir_all(root.path()).unwrap();
        let db = Arc::new(SledEventDatabase::new(root.path()).unwrap());
        (
            BasicProcessor::new(db.clone(), None),
            EventStorage::new(db.clone()),
        )
    };

    let bob_icp = bob
        .incept(Some(vec![witness.prefix.clone()]), None)
        .unwrap();
    // bob.rotate().unwrap();

    let bob_pref = bob.prefix().clone();

    // send bobs icp to witness to have his keys
    let bob_icp_msg = Message::Notice(Notice::Event(bob_icp.clone()))
        .to_cesr()
        .unwrap();
    witness.parse_and_process_notices(&bob_icp_msg)?;

    // construct bobs ksn msg in rpy made by witness
    let signed_rpy = witness.get_signed_ksn_for_prefix(&bob_pref, signer_arc.clone())?;

    // Process reply message before having any bob's events in db.
    alice_processor.process_op_reply(&signed_rpy)?;
    let ksn_db = alice_storage.get_last_ksn_reply(
        &signed_rpy.reply.get_prefix(),
        &signed_rpy.signature.get_signer().unwrap(),
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
        &signed_rpy.signature.get_signer().unwrap(),
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
        &signed_rpy.signature.get_signer().unwrap(),
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
        &signed_rpy.signature.get_signer().unwrap(),
    );
    assert!(matches!(ksn_db, Some(_)));
    let ksn_from_db_digest = ksn_db.unwrap().reply.get_digest();
    assert_eq!(ksn_from_db_digest, out_of_order_ksn_digest);

    Ok(())
}

#[test]
fn test_mbx() {
    use std::sync::Mutex;

    use keri::signer::CryptoBox;

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
            let escrow_db_controller = Arc::new(EscrowDb::new(root.path()).unwrap());
            let key_manager = Arc::new(Mutex::new(CryptoBox::new().unwrap()));
            SimpleController::new(
                Arc::clone(&db_controller),
                Arc::clone(&escrow_db_controller),
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
        let mbx_msg = controller.query_mailbox(&witness.prefix);
        let mbx_msg = Message::Op(mbx_msg).to_cesr().unwrap();
        let receipts = witness.parse_and_process_ops(&mbx_msg).unwrap();

        if let PossibleResponse::Mbx(mbx) = &receipts[0] {
            assert_eq!(receipts.len(), 1);
            let receipt = mbx.receipt[0].clone();

            assert_eq!(receipt.body.event.sn, 0);
            assert_eq!(receipt.body.event.prefix, controller.prefix().clone());
        }
    }
}

#[test]
fn test_invalid_notice() {
    use std::sync::Mutex;

    use keri::signer::CryptoBox;

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
            let escrow_db_controller = Arc::new(EscrowDb::new(root.path()).unwrap());
            let key_manager = Arc::new(Mutex::new(CryptoBox::new().unwrap()));
            SimpleController::new(
                Arc::clone(&db_controller),
                Arc::clone(&escrow_db_controller),
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

    // create invalid inception events
    for controller in &mut controllers {
        let incept_event = controller
            .incept(Some(vec![witness.prefix.clone()]), Some(1))
            .unwrap();

        // change identifier
        let mut invalid_event = incept_event.clone();
        invalid_event.event_message.event.content.prefix = IdentifierPrefix::Basic(
            BasicPrefix::new(Basic::Ed25519, PublicKey::new(vec![0; 32])),
        );
        let result = witness.process_notice(Notice::Event(invalid_event));
        // TODO: use better error variant
        assert!(matches!(result, Err(Error::SemanticError(_))));

        // remove signatures
        let mut incept_event_unsigned = incept_event.clone();
        incept_event_unsigned.signatures.clear();

        let result = witness.process_notice(Notice::Event(incept_event_unsigned));

        assert!(matches!(result, Ok(())));
    }

    // query witness
    for controller in controllers {
        let mbx_msg = controller.query_mailbox(&witness.prefix);
        let mbx_msg = Message::Op(mbx_msg).to_cesr().unwrap();
        let result = witness.parse_and_process_ops(&mbx_msg);

        // should not be able to query because the inception events didn't go through
        assert!(matches!(
            result,
            Err(WitnessError::QueryFailed(
                SignedQueryError::UnknownSigner { ref id }
            )) if id == controller.prefix()
        ));
    }
}

#[test]
pub fn test_multisig() -> Result<(), WitnessError> {
    let signer = Signer::new();
    let signer_arc = Arc::new(signer);
    let witness = {
        let witness_root = Builder::new().prefix("test-db").tempdir().unwrap();
        let witness_root_oobi = Builder::new().prefix("test-db").tempdir().unwrap();
        let path = witness_root.path();
        Witness::new(signer_arc.clone(), path, witness_root_oobi.path())?
    };

    // Init first controller.
    let mut cont1 = {
        // Create test db and event processor.
        let cont1_key_manager = Arc::new(Mutex::new(CryptoBox::new()?));
        let root = Builder::new().prefix("test-db").tempdir().unwrap();
        let oobi_root = Builder::new().prefix("cont1-db-oobi").tempdir().unwrap();
        let db = Arc::new(SledEventDatabase::new(root.path()).unwrap());
        let cont1_escrow_db = Arc::new(EscrowDb::new(root.path())?);

        SimpleController::new(
            Arc::clone(&db),
            Arc::clone(&cont1_escrow_db),
            Arc::clone(&cont1_key_manager),
            oobi_root.path(),
        )?
    };
    let icp_1 = cont1.incept(Some(vec![witness.prefix.clone()]), Some(1))?;
    witness.process_notice(Notice::Event(icp_1.clone()))?;
    let receipts1 = witness
        .get_mailbox_messages(cont1.prefix())?
        .receipt
        .into_iter()
        .map(|r| Message::Notice(Notice::NontransferableRct(r)))
        .collect::<Vec<_>>();
    cont1.process(&receipts1)?;

    // Init second controller.
    let mut cont2 = {
        // Create test db and event processor.
        let cont2_key_manager = Arc::new(Mutex::new(CryptoBox::new()?));
        let root = Builder::new().prefix("test-db").tempdir().unwrap();
        let oobi_root = Builder::new().prefix("cont2-db-oobi").tempdir().unwrap();
        let db = Arc::new(SledEventDatabase::new(root.path()).unwrap());
        let cont2_escrow_db = Arc::new(EscrowDb::new(root.path())?);

        SimpleController::new(
            Arc::clone(&db),
            Arc::clone(&cont2_escrow_db),
            Arc::clone(&cont2_key_manager),
            oobi_root.path(),
        )?
    };
    let icp_2 = cont2.incept(Some(vec![witness.prefix.clone()]), Some(1))?;
    witness.process_notice(Notice::Event(icp_2.clone()))?;
    let receipts2 = witness
        .get_mailbox_messages(cont2.prefix())?
        .receipt
        .into_iter()
        .map(|r| Message::Notice(Notice::NontransferableRct(r)))
        .collect::<Vec<_>>();
    cont2.process(&receipts2)?;

    // Process inceptions of other group participants
    cont2.process(&[Message::Notice(Notice::Event(icp_1))])?;
    cont2.process(&receipts1)?;
    cont1.process(&[Message::Notice(Notice::Event(icp_2))])?;
    cont1.process(&receipts2)?;

    let (group_icp, exchange_messages) = cont1.group_incept(
        vec![cont2.prefix().clone()],
        &SignatureThreshold::Simple(2),
        Some(vec![witness.prefix.clone()]),
        Some(1),
    )?;
    witness.process_notice(Notice::Event(group_icp.clone()))?;

    let group_id = group_icp.event_message.event.get_prefix();
    assert_eq!(exchange_messages.len(), 1);

    witness.process_op(Op::Exchange(exchange_messages[0].clone()))?;

    // Controller2 asks witness about his mailbox.
    let mbx_msg = cont2.query_mailbox(&witness.prefix);
    let response = witness.process_op(mbx_msg).unwrap();
    if let Some(PossibleResponse::Mbx(MailboxResponse { receipt, multisig, delegate: _ })) = response {
        assert_eq!(receipt.len(), 1);
        assert_eq!(multisig.len(), 1);

        let group_icp_to_sign = multisig[0].clone();

        let signed_icp = cont2.process_multisig(group_icp_to_sign)?.unwrap();
        let exn_from_cont2 = cont2.create_forward_message(&cont1.prefix(), &signed_icp, ForwardTopic::Multisig)?;
        // Send it to witness
        witness.process_notice(Notice::Event(signed_icp.clone()))?;
        witness.process_op(Op::Exchange(exn_from_cont2))?;
    };
    // Controller2 didin't accept group icp yet because of lack of witness receipt.
    let state = cont2.get_state_for_id(&group_id)?;
    assert_eq!(state, None);
    // Also Controller1 didin't get his exn and receipts.
    let state = cont1.get_state_for_id(&group_id)?;
    assert_eq!(state, None);

    let state = witness.event_storage.get_state(&group_id)?.unwrap();
    assert_eq!(state.sn, 0);

    let group_query_message = cont1.query_groups_mailbox(&witness.prefix)[0].clone();

    let res = witness.process_op(Op::Query(group_query_message))?;
    let receipts = match res {
        Some(PossibleResponse::Mbx(mbx)) => mbx.receipt,
        _ => unreachable!(),
    };

    let group_receipt = receipts
        .into_iter()
        .map(|r| Message::Notice(Notice::NontransferableRct(r)))
        .collect::<Vec<_>>();
    cont2.process(&group_receipt)?;
    let state = cont2.get_state_for_id(&group_id)?;
    assert_eq!(state.unwrap().sn, 0);

    // Controller1 asks witness about his mailbox.
    let mbx_msg = cont1.query_mailbox(&witness.prefix);
    let response = witness.process_op(mbx_msg).unwrap();
    if let Some(PossibleResponse::Mbx(MailboxResponse { receipt, multisig, delegate: _ })) = response {
        assert_eq!(receipt.len(), 1);
        assert_eq!(multisig.len(), 1);

        let group_icp = multisig[0].clone();
        // Process partially signed group icp
        cont1.process_multisig(group_icp)?;
    };
    // Process witness receipt of group event
    cont1.process(&group_receipt)?;
    let state = cont1.get_state_for_id(&group_id)?;
    assert_eq!(state.unwrap().sn, 0);

    Ok(())
}

