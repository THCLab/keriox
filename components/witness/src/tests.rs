use std::sync::{Arc, Mutex};

use keri_core::{
    actor::{
        error::ActorError,
        possible_response::PossibleResponse,
        prelude::{HashFunctionCode, SerializationFormats},
        simple_controller::SimpleController,
        SignedQueryError,
    },
    database::redb::RedbDatabase,
    error::Error,
    event::sections::{
        seal::{EventSeal, Seal},
        threshold::SignatureThreshold,
    },
    event_message::signed_event_message::{Message, Notice, Op, SignedEventMessage},
    keys::PublicKey,
    mailbox::{exchange::ForwardTopic, MailboxResponse},
    prefix::{BasicPrefix, IdentifierPrefix, SelfSigningPrefix},
    processor::{
        basic_processor::BasicProcessor, escrow::EscrowConfig, event_storage::EventStorage,
        Processor,
    },
    query::query_event::{LogsQueryArgs, SignedQueryMessage},
    signer::{CryptoBox, Signer},
};
use tempfile::Builder;
use url::Url;

use crate::{witness::Witness, witness_processor::WitnessEscrowConfig};

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

        let events_root = Builder::new().tempfile().unwrap();
        let events_db = Arc::new(RedbDatabase::new(events_root.path()).unwrap());

        let key_manager = {
            use keri_core::signer::CryptoBox;
            Arc::new(Mutex::new(CryptoBox::new()?))
        };
        SimpleController::new(Arc::clone(&events_db), key_manager, EscrowConfig::default())?
    };

    assert_eq!(controller.get_state(), None);

    let first_witness = {
        let root_witness = Builder::new().prefix("test-db1").tempdir().unwrap();
        std::fs::create_dir_all(root_witness.path()).unwrap();
        Witness::setup(
            url::Url::parse("http://some/url").unwrap(),
            root_witness.path(),
            Some(seed1.into()),
            WitnessEscrowConfig::default(),
        )
        .unwrap()
    };

    let second_witness = {
        let root_witness = Builder::new().prefix("test-db1").tempdir().unwrap();
        std::fs::create_dir_all(root_witness.path()).unwrap();
        Witness::setup(
            url::Url::parse("http://some/url").unwrap(),
            root_witness.path(),
            Some(seed2.into()),
            WitnessEscrowConfig::default(),
        )
        .unwrap()
    };

    // Get inception event.
    let inception_event = controller.incept(
        Some(vec![
            first_witness.prefix.clone(),
            second_witness.prefix.clone(),
        ]),
        Some(2),
        None,
    )?;

    // Shouldn't be accepted in controllers kel, because of missing witness receipts
    assert_eq!(controller.get_state(), None);

    let receipts = [&first_witness, &second_witness]
        .iter()
        .flat_map(|w| {
            let not = Notice::Event(inception_event.clone());
            w.process_notice(not).unwrap();
            w.event_storage
                .mailbox_data.as_ref().unwrap()
                .get_mailbox_receipts(controller.prefix(), 0)
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
            .get_state(&controller.prefix())
            .unwrap()
            .sn,
        0
    );
    assert_eq!(
        second_witness
            .event_storage
            .get_state(&controller.prefix())
            .unwrap()
            .sn,
        0
    );

    // process first receipt
    controller
        .process(&[Message::Notice(receipts[0].clone())])
        .unwrap();

    // Still not fully witnessed
    assert_eq!(controller.get_state(), None);

    // process second receipt
    controller
        .process(&[Message::Notice(receipts[1].clone())])
        .unwrap();

    // Now fully witnessed, should be in kel
    assert_eq!(controller.get_state().map(|state| state.sn), Some(0));
    assert_eq!(
        controller
            .get_state()
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
            .get_state(&controller.prefix())
            .map(|state| state.sn),
        Some(0)
    );
    assert_eq!(
        second_witness
            .event_storage
            .get_state(&controller.prefix())
            .map(|state| state.sn),
        Some(0)
    );

    let rotation_event = controller.rotate(None, Some(&[second_witness.prefix.clone()]), Some(1));
    // Rotation not yet accepted by controller, missing receipts
    assert_eq!(controller.get_state().unwrap().sn, 0);
    first_witness.process_notice(Notice::Event(rotation_event?))?;
    // first_witness.respond(signer_arc.clone())?;
    let first_receipt = first_witness
        .event_storage
        .mailbox_data.as_ref().unwrap()
        .get_mailbox_receipts(controller.prefix(), 0)
        .unwrap()
        .map(Notice::NontransferableRct)
        .map(Message::Notice)
        .collect::<Vec<_>>();

    // Receipt accepted by witness, because his the only designated witness
    assert_eq!(
        first_witness
            .event_storage
            .get_state(&controller.prefix())
            .unwrap()
            .sn,
        1
    );

    // process receipt by controller
    controller.process(&first_receipt)?;
    assert_eq!(controller.get_state().unwrap().sn, 1);

    assert_eq!(
        controller
            .get_state()
            .map(|state| state.witness_config.witnesses),
        Some(vec![first_witness.prefix.clone(),])
    );

    Ok(())
}

#[test]
fn test_qry_rpy() -> Result<(), ActorError> {
    use keri_core::{
        prefix::IndexedSignature,
        query::{
            query_event::{QueryEvent, QueryRoute, SignedKelQuery},
            reply_event::ReplyRoute,
        },
        signer::{KeyManager, Signer},
    };
    use tempfile::Builder;

    // Create test db and event processor.
    let redb_root = Builder::new().tempfile().unwrap();
    let alice_redb = Arc::new(RedbDatabase::new(redb_root.path()).unwrap());
    let bob_redb_root = Builder::new().tempfile().unwrap();
    let bob_redb = Arc::new(RedbDatabase::new(bob_redb_root.path()).unwrap());

    let witness_root = Builder::new().prefix("test-db").tempdir().unwrap();
    let signer = Signer::new();
    let signer_arc = Arc::new(signer);
    let witness = Witness::new(
        Url::parse("http://example.com").unwrap(),
        signer_arc,
        witness_root.path(),
        WitnessEscrowConfig::default(),
    )
    .unwrap();

    let alice_key_manager = Arc::new(Mutex::new({
        use keri_core::signer::CryptoBox;
        CryptoBox::new()?
    }));

    // Init alice.
    let mut alice = SimpleController::new(
        Arc::clone(&alice_redb),
        Arc::clone(&alice_key_manager),
        EscrowConfig::default(),
    )?;

    let bob_key_manager = Arc::new(Mutex::new({
        use keri_core::signer::CryptoBox;
        CryptoBox::new()?
    }));

    // Init bob.
    let mut bob = SimpleController::new(
        Arc::clone(&bob_redb),
        Arc::clone(&bob_key_manager),
        EscrowConfig::default(),
    )?;

    let bob_icp = bob.incept(None, None, None).unwrap();
    // bob.rotate(None, None, None).unwrap();

    let bob_pref = bob.prefix();

    let alice_icp = alice.incept(Some(vec![witness.prefix.clone()]), None, None)?;
    // send alices icp to witness
    witness.process_notice(Notice::Event(alice_icp))?;
    // send receipts to alice
    let receipt_to_alice = witness
        .event_storage
        .mailbox_data.as_ref().unwrap()
        .get_mailbox_receipts(alice.prefix(), 0)
        .unwrap()
        .map(Notice::NontransferableRct)
        .map(Message::Notice)
        .collect::<Vec<_>>();
    alice.process(&receipt_to_alice)?;

    // send bobs icp to witness to have his keys
    witness.process_notice(Notice::Event(bob_icp))?;

    // Bob asks about alices key state
    // construct qry message to ask of alice key state message
    let query_args = LogsQueryArgs {
        i: alice.prefix().clone(),
        s: None,
        src: Some(alice.prefix().clone()),
        limit: None,
    };

    let qry = QueryEvent::new_query(
        QueryRoute::Ksn {
            args: query_args,
            reply_route: String::from(""),
        },
        SerializationFormats::JSON,
        HashFunctionCode::Blake3_256,
    );

    // sign message by bob
    let signature = IndexedSignature::new_both_same(
        SelfSigningPrefix::Ed25519Sha512(
            Arc::clone(&bob_key_manager)
                .lock()
                .unwrap()
                .sign(&serde_json::to_vec(&qry).unwrap())?,
        ),
        0,
    );
    // Qry message signed by Bob
    let query = SignedQueryMessage::KelQuery(SignedKelQuery::new_trans(
        qry,
        bob_pref.to_owned(),
        vec![signature],
    ));

    let response = witness.process_query(query)?;

    // assert_eq!(response.len(), 1);
    if let Some(PossibleResponse::Kel(response)) = response {
        match &response[0] {
            Message::Op(Op::Reply(rpy)) => {
                if let ReplyRoute::Ksn(_id, ksn) = rpy.reply.get_route() {
                    assert_eq!(&ksn.state, &alice.get_state().unwrap())
                }
            }
            _ => unreachable!(),
        }
    }

    // Bob asks about alices kel
    // construct qry message to ask of alice kel
    let query_args = LogsQueryArgs {
        i: alice.prefix().clone(),
        s: None,
        src: None,
        limit: None,
    };
    let qry = QueryEvent::new_query(
        QueryRoute::Logs {
            args: query_args,
            reply_route: String::from(""),
        },
        SerializationFormats::JSON,
        HashFunctionCode::Blake3_256,
    );

    // sign message by bob
    let signature = IndexedSignature::new_both_same(
        SelfSigningPrefix::Ed25519Sha512(
            Arc::clone(&bob_key_manager)
                .lock()
                .unwrap()
                .sign(&serde_json::to_vec(&qry).unwrap())?,
        ),
        0,
    );
    // Qry message signed by Bob
    let query = SignedQueryMessage::KelQuery(SignedKelQuery::new_trans(
        qry,
        bob_pref.to_owned(),
        vec![signature],
    ));

    let response = witness.process_query(query)?;

    let alice_kel = alice
        .storage
        .get_kel_messages_with_receipts_all(alice.prefix())?
        .into_iter()
        .flatten()
        .map(Message::Notice)
        .collect::<Vec<_>>();
    assert_eq!(response, Some(PossibleResponse::Kel(alice_kel)));

    Ok(())
}

#[test]
pub fn test_key_state_notice() -> Result<(), Error> {
    use keri_core::{
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
        Witness::new(
            Url::parse("http://example.com").unwrap(),
            signer_arc.clone(),
            path,
            WitnessEscrowConfig::default(),
        )
        .unwrap()
    };

    // Init bob.
    let mut bob = {
        // Create test db and event processor.
        let root = Builder::new().prefix("test-db").tempdir().unwrap();
        std::fs::create_dir_all(root.path()).unwrap();
        let bob_redb_root = Builder::new().tempfile().unwrap();
        let bob_redb = Arc::new(RedbDatabase::new(bob_redb_root.path()).unwrap());

        let bob_key_manager = Arc::new(Mutex::new(CryptoBox::new()?));
        SimpleController::new(
            Arc::clone(&bob_redb),
            Arc::clone(&bob_key_manager),
            EscrowConfig::default(),
        )?
    };

    let (alice_processor, alice_storage) = {
        let root = Builder::new().prefix("test-db2").tempdir().unwrap();
        std::fs::create_dir_all(root.path()).unwrap();

        let alice_redb_root = Builder::new().tempfile().unwrap();
        let alice_redb = Arc::new(RedbDatabase::new(alice_redb_root.path()).unwrap());
        (
            BasicProcessor::new(alice_redb.clone(), None),
            EventStorage::new(alice_redb.clone()),
        )
    };

    let bob_icp = bob
        .incept(Some(vec![witness.prefix.clone()]), None, None)
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

    let ksn_from_db_digest = ksn_db.unwrap().reply.digest()?;
    let processed_ksn_digest = new_reply.reply.digest()?;
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
    let ksn_from_db_digest = ksn_db.unwrap().reply.digest()?;
    let out_of_order_ksn_digest = trans_rpy.reply.digest()?;
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
    let ksn_from_db_digest = ksn_db.unwrap().reply.digest()?;
    assert_eq!(ksn_from_db_digest, out_of_order_ksn_digest);

    Ok(())
}

#[test]
fn test_mbx() {
    use std::sync::Mutex;

    use keri_core::signer::CryptoBox;

    let signer = Arc::new(Signer::new());

    let mut controllers = (0..2)
        .map(|i| {
            let root = tempfile::Builder::new()
                .prefix(&format!("test-ctrl-{i}"))
                .tempdir()
                .unwrap();
            std::fs::create_dir_all(root.path()).unwrap();
            let redb_root = Builder::new().tempfile().unwrap();
            let redb = Arc::new(RedbDatabase::new(redb_root.path()).unwrap());
            let key_manager = Arc::new(Mutex::new(CryptoBox::new().unwrap()));
            SimpleController::new(Arc::clone(&redb), key_manager, EscrowConfig::default()).unwrap()
        })
        .collect::<Vec<_>>();

    let witness = {
        let root = tempfile::Builder::new()
            .prefix("test-witness")
            .tempdir()
            .unwrap();
        std::fs::create_dir_all(root.path()).unwrap();
        Witness::new(
            Url::parse("http://example.com").unwrap(),
            signer,
            root.path(),
            WitnessEscrowConfig::default(),
        )
        .unwrap()
    };

    // create inception events
    for controller in &mut controllers {
        let incept_event = controller
            .incept(Some(vec![witness.prefix.clone()]), Some(1), None)
            .unwrap();

        // send to witness
        witness
            .process_notice(Notice::Event(incept_event.clone()))
            .unwrap();
    }

    // query witness
    for controller in controllers {
        let mbx_msg = controller.query_mailbox(&witness.prefix);
        let mbx_msg = Message::Op(Op::Query(mbx_msg)).to_cesr().unwrap();
        let receipts = witness.parse_and_process_queries(&mbx_msg).unwrap();

        if let PossibleResponse::Mbx(mbx) = &receipts[0] {
            assert_eq!(receipts.len(), 1);
            let receipt = mbx.receipt[0].clone();

            assert_eq!(receipt.body.sn, 0);
            assert_eq!(receipt.body.prefix, controller.prefix().clone());
        }
    }
}

#[test]
fn test_invalid_notice() {
    use std::sync::Mutex;

    use keri_core::signer::CryptoBox;

    let signer = Arc::new(Signer::new());

    let mut controllers = (0..2)
        .map(|i| {
            let root = tempfile::Builder::new()
                .prefix(&format!("test-ctrl-{i}"))
                .tempdir()
                .unwrap();
            std::fs::create_dir_all(root.path()).unwrap();
            let redb_root = Builder::new().tempfile().unwrap();
            let redb = Arc::new(RedbDatabase::new(redb_root.path()).unwrap());
            let key_manager = Arc::new(Mutex::new(CryptoBox::new().unwrap()));
            SimpleController::new(Arc::clone(&redb), key_manager, EscrowConfig::default()).unwrap()
        })
        .collect::<Vec<_>>();

    let witness = {
        let root = tempfile::Builder::new()
            .prefix("test-witness")
            .tempdir()
            .unwrap();
        if !std::fs::exists(root.path()).unwrap() {
            std::fs::create_dir_all(root.path()).unwrap();
        }
        Witness::new(
            Url::parse("http://example.com").unwrap(),
            signer,
            root.path(),
            WitnessEscrowConfig::default(),
        )
        .unwrap()
    };

    // create invalid inception events
    for controller in &mut controllers {
        let incept_event = controller
            .incept(Some(vec![witness.prefix.clone()]), Some(1), None)
            .unwrap();

        // change identifier
        let mut invalid_event = incept_event.clone();
        invalid_event.event_message.data.prefix =
            IdentifierPrefix::Basic(BasicPrefix::Ed25519(PublicKey::new(vec![0; 32])));
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
        let mbx_msg = Message::Op(Op::Query(mbx_msg)).to_cesr().unwrap();
        println!("{}", String::from_utf8(mbx_msg.clone()).unwrap());
        let result = witness.parse_and_process_queries(&mbx_msg);

        // should not be able to query because the inception events didn't go through
        dbg!(&result);
        assert!(matches!(
            result,
            Err(ActorError::QueryError(SignedQueryError::KeriError(
                keri_core::error::Error::UnknownSigner(ref id))
            )) if id == controller.prefix()
        ));
    }
}

#[test]
pub fn test_multisig() -> Result<(), ActorError> {
    let signer = Signer::new();
    let signer_arc = Arc::new(signer);
    let witness = {
        let witness_root = Builder::new().prefix("test-db").tempdir().unwrap();
        let path = witness_root.path();
        Witness::new(
            Url::parse("http://example.com").unwrap(),
            signer_arc,
            path,
            WitnessEscrowConfig::default(),
        )
        .unwrap()
    };

    // Init first controller.
    let mut cont1 = {
        // Create test db and event processor.
        let cont1_key_manager = Arc::new(Mutex::new(CryptoBox::new()?));
        let redb_root = Builder::new().tempfile().unwrap();
        let redb = Arc::new(RedbDatabase::new(redb_root.path()).unwrap());

        SimpleController::new(
            Arc::clone(&redb),
            Arc::clone(&cont1_key_manager),
            EscrowConfig::default(),
        )?
    };
    let icp_1 = cont1.incept(Some(vec![witness.prefix.clone()]), Some(1), None)?;
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
        let redb_root = Builder::new().tempfile().unwrap();
        let redb = Arc::new(RedbDatabase::new(redb_root.path()).unwrap());

        SimpleController::new(
            Arc::clone(&redb),
            Arc::clone(&cont2_key_manager),
            EscrowConfig::default(),
        )?
    };
    let icp_2 = cont2.incept(Some(vec![witness.prefix.clone()]), Some(1), None)?;
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
        None,
    )?;
    witness.process_notice(Notice::Event(group_icp.clone()))?;

    let group_id = group_icp.event_message.data.get_prefix();
    assert_eq!(exchange_messages.len(), 1);

    witness.process_exchange(exchange_messages[0].clone())?;

    // Controller2 asks witness about his mailbox.
    let mbx_msg = cont2.query_mailbox(&witness.prefix);
    let response = witness.process_query(mbx_msg).unwrap();
    if let Some(PossibleResponse::Mbx(MailboxResponse {
        receipt,
        multisig,
        delegate: _,
    })) = response
    {
        assert_eq!(receipt.len(), 1);
        assert_eq!(multisig.len(), 1);

        let group_icp_to_sign = multisig[0].clone();

        let signed_icp = cont2.process_multisig(group_icp_to_sign)?.unwrap();
        let exn_from_cont2 =
            cont2.create_forward_message(&cont1.prefix(), &signed_icp, ForwardTopic::Multisig)?;
        // Send it to witness
        witness.process_notice(Notice::Event(signed_icp.clone()))?;
        witness.process_exchange(exn_from_cont2)?;
    };
    // Controller2 didin't accept group icp yet because of lack of witness receipt.
    let state = cont2.get_state_for_id(&group_id);
    assert_eq!(state, None);
    // Also Controller1 didin't get his exn and receipts.
    let state = cont1.get_state_for_id(&group_id);
    assert_eq!(state, None);

    let state = witness.event_storage.get_state(&group_id).unwrap();
    assert_eq!(state.sn, 0);

    let group_query_message = cont1.query_groups_mailbox(&witness.prefix)[0].clone();

    let res = witness.process_query(group_query_message)?;
    let receipts = match res {
        Some(PossibleResponse::Mbx(mbx)) => mbx.receipt,
        _ => unreachable!(),
    };

    let group_receipt = receipts
        .into_iter()
        .map(|r| Message::Notice(Notice::NontransferableRct(r)))
        .collect::<Vec<_>>();
    cont2.process(&group_receipt)?;
    let state = cont2.get_state_for_id(&group_id);
    assert_eq!(state.unwrap().sn, 0);

    // Controller1 asks witness about his mailbox.
    let mbx_msg = cont1.query_mailbox(&witness.prefix);
    let response = witness.process_query(mbx_msg).unwrap();
    if let Some(PossibleResponse::Mbx(MailboxResponse {
        receipt,
        multisig,
        delegate: _,
    })) = response
    {
        assert_eq!(receipt.len(), 1);
        assert_eq!(multisig.len(), 1);

        let group_icp = multisig[0].clone();
        // Process partially signed group icp
        cont1.process_multisig(group_icp)?;
    };
    // Process witness receipt of group event
    cont1.process(&group_receipt)?;
    let state = cont1.get_state_for_id(&group_id);
    assert_eq!(state.unwrap().sn, 0);

    Ok(())
}

// Helper function that creates controller, makes and publish its inception event.
fn setup_controller(witness: &Witness) -> Result<SimpleController<CryptoBox, RedbDatabase>, Error> {
    let mut cont1 = {
        // Create test db and event processor.
        let cont1_key_manager = Arc::new(Mutex::new(CryptoBox::new()?));
        let redb_root = Builder::new().tempfile().unwrap();
        let redb = Arc::new(RedbDatabase::new(redb_root.path()).unwrap());

        SimpleController::new(
            Arc::clone(&redb),
            Arc::clone(&cont1_key_manager),
            EscrowConfig::default(),
        )?
    };
    let icp_1 = cont1.incept(Some(vec![witness.prefix.clone()]), Some(1), None)?;
    witness.process_notice(Notice::Event(icp_1.clone()))?;
    let receipts1 = witness
        .get_mailbox_messages(cont1.prefix())?
        .receipt
        .into_iter()
        .map(|r| Message::Notice(Notice::NontransferableRct(r)))
        .collect::<Vec<_>>();
    cont1.process(&receipts1)?;
    Ok(cont1)
}

#[test]
pub fn test_delegated_multisig() -> Result<(), ActorError> {
    let signer = Signer::new();
    let signer_arc = Arc::new(signer);
    let witness = {
        let witness_root = Builder::new().prefix("test-db").tempdir().unwrap();
        let path = witness_root.path();
        Witness::new(
            Url::parse("http://example.com").unwrap(),
            signer_arc,
            path,
            WitnessEscrowConfig::default(),
        )
        .unwrap()
    };

    // Init first controller.
    let mut cont1 = setup_controller(&witness)?;
    // Init second controller.
    let mut cont2 = setup_controller(&witness)?;

    let delegator = setup_controller(&witness)?;

    // Process inceptions of other group participants
    let cont1_kel = cont1
        .storage
        .get_kel_messages_with_receipts_all(cont1.prefix())?
        .unwrap()
        .into_iter()
        .map(|not| Message::Notice(not))
        .collect::<Vec<_>>();
    let cont2_kel = cont2
        .storage
        .get_kel_messages_with_receipts_all(cont2.prefix())?
        .unwrap()
        .into_iter()
        .map(|not| Message::Notice(not))
        .collect::<Vec<_>>();
    let delegator_kel = delegator
        .storage
        .get_kel_messages_with_receipts_all(delegator.prefix())?
        .unwrap()
        .into_iter()
        .map(|not| Message::Notice(not))
        .collect::<Vec<_>>();

    cont2.process(&cont1_kel)?;
    cont1.process(&cont2_kel)?;
    cont1.process(&delegator_kel)?;
    cont2.process(&delegator_kel)?;

    // Make delegated inception event for group
    let (group_dip, exchange_messages) = cont1.group_incept(
        vec![cont2.prefix().clone()],
        &SignatureThreshold::Simple(2),
        Some(vec![witness.prefix.clone()]),
        Some(1),
        Some(delegator.prefix().clone()),
    )?;

    let group_id = group_dip.event_message.data.get_prefix();
    let dip_digest = group_dip.event_message.digest()?;
    assert_eq!(exchange_messages.len(), 1);

    // Send exchange message from controller 1 to controller 2
    witness.process_exchange(exchange_messages[0].clone())?;

    // Controller2 asks witness about his mailbox.
    let mbx_msg = cont2.query_mailbox(&witness.prefix);
    let response = witness.process_query(mbx_msg).unwrap();
    if let Some(PossibleResponse::Mbx(MailboxResponse {
        receipt: _,
        multisig,
        delegate: _,
    })) = response
    {
        assert_eq!(multisig.len(), 1);

        let group_icp_to_sign = multisig[0].clone();
        let signed_dip = cont2.process_multisig(group_icp_to_sign)?.unwrap();
        // Construct exn message (will be stored in group identidfier mailbox)
        let exn_from_cont2 =
            cont2.create_forward_message(&group_id, &signed_dip, ForwardTopic::Multisig)?;
        // Send it to witness
        witness.process_exchange(exn_from_cont2)?;
    };

    // Controller1 asks witness about group mailbox to have fully signed dip.
    let mbx_msg = cont1.query_groups_mailbox(&witness.prefix);
    let response = witness.process_query(mbx_msg[0].clone()).unwrap();
    if let Some(PossibleResponse::Mbx(MailboxResponse {
        receipt: _,
        multisig,
        delegate: _,
    })) = response
    {
        assert_eq!(multisig.len(), 1);

        let group_icp = multisig[0].clone();
        cont1.process_multisig(group_icp)?;
    };

    // Controller2 didn't accept group dip yet because of lack of witness receipt and delegating event.
    let state = cont2.get_state_for_id(&group_id);
    assert_eq!(state, None);
    // Also Controller1 didn't accept it.
    let state = cont1.get_state_for_id(&group_id);
    assert_eq!(state, None);

    // Request delegating confirmation
    // TODO: how to get dip with all signatures? get signed dip from cont escrow
    let dip = cont2
        .delegation_escrow
        .get_event_by_sn_and_digest(0, &delegator.prefix(), &dip_digest)
        .unwrap();

    let delegation_request =
        cont1.create_forward_message(delegator.prefix(), &dip, ForwardTopic::Delegate)?;

    witness.process_exchange(delegation_request.clone())?;

    // Delegator gets mailbox
    let mbx_msg = delegator.query_mailbox(&witness.prefix);
    let response = witness.process_query(mbx_msg).unwrap();
    if let Some(PossibleResponse::Mbx(MailboxResponse {
        receipt,
        multisig: _,
        delegate,
    })) = response
    {
        assert_eq!(receipt.len(), 1);
        assert_eq!(delegate.len(), 1);

        let group_icp_to_confirm = delegate[0].clone();
        delegator.process(&[Message::Notice(Notice::Event(group_icp_to_confirm))])?;

        // make delegating event
        let seal = Seal::Event(EventSeal::new(group_id.clone(), 0, dip_digest.clone()));

        let ixn = delegator.anchor(&vec![seal])?;
        // Send it to witness
        witness.process_notice(Notice::Event(ixn.clone()))?;

        let state = witness.event_storage.get_state(delegator.prefix()).unwrap();
        assert_eq!(state.sn, 1);
    };

    // Delegator gets mailbox again for receipts
    let mbx_msg = delegator.query_mailbox(&witness.prefix);
    let response = witness.process_query(mbx_msg).unwrap();
    if let Some(PossibleResponse::Mbx(MailboxResponse {
        receipt,
        multisig: _,
        delegate: _,
    })) = response
    {
        assert_eq!(receipt.len(), 2);

        let ixn_receipt = receipt[1].clone();
        delegator.process(&[Message::Notice(Notice::NontransferableRct(
            ixn_receipt.clone(),
        ))])?;

        // TODO return event with attached receipts
        let ixn = delegator
            .storage
            .get_event_at_sn(delegator.prefix(), 1)
            .unwrap()
            .signed_event_message;
        let attached_witness_sig = ixn_receipt.signatures;

        let ixn_with_receipt = SignedEventMessage {
            witness_receipts: Some(attached_witness_sig),
            ..ixn
        };

        // Forward delegating event to group id
        let exn_from_delegator = delegator.create_forward_message(
            &group_id,
            &ixn_with_receipt,
            ForwardTopic::Delegate,
        )?;

        // Send it to witness
        witness.process_exchange(exn_from_delegator)?;
    };

    // Child ask about group mailbox
    for controller in vec![&cont1, &cont2] {
        let mbx_query = controller.query_groups_mailbox(&witness.prefix);

        let response = witness.process_query(mbx_query[0].clone()).unwrap();
        if let Some(PossibleResponse::Mbx(MailboxResponse {
            receipt: _,
            multisig: _,
            delegate,
        })) = response
        {
            assert_eq!(delegate.len(), 1);
            controller.process(&[Message::Notice(Notice::Event(delegate[0].clone()))])?;
        };
    }
    let state = cont1.get_state_for_id(&delegator.prefix());
    assert_eq!(state.unwrap().sn, 1);

    // del escrow should be empty because delegating event was provided
    let delegation_escrowed =
        cont1
            .delegation_escrow
            .get_event_by_sn_and_digest(0, &group_id, &dip_digest);
    assert!(delegation_escrowed.is_none());

    let dip_with_delegator_seal = cont1
        .not_fully_witnessed_escrow
        .get_event_by_sn_and_digest(0, &group_id, &dip_digest)
        .unwrap()
        .unwrap();

    let state = witness
        .event_storage
        .get_state(&delegator.prefix())
        .unwrap();
    assert_eq!(state.sn, 1);

    // publish delegated event to witness
    witness.process_notice(Notice::Event(dip_with_delegator_seal.clone()))?;
    let state = witness.event_storage.get_state(&group_id).unwrap();
    assert_eq!(state.sn, 0);

    // Child ask about mailbox
    for controller in vec![&cont1, &cont2] {
        let mbx_query = controller.query_groups_mailbox(&witness.prefix);
        let response = witness.process_query(mbx_query[0].clone()).unwrap();
        if let Some(PossibleResponse::Mbx(MailboxResponse {
            receipt,
            multisig: _,
            delegate: _,
        })) = response
        {
            assert_eq!(receipt.len(), 1);
            controller.process(&[Message::Notice(Notice::NontransferableRct(
                receipt[0].clone(),
            ))])?;
        };

        let state = controller.get_state_for_id(&group_id);
        assert_eq!(state.unwrap().sn, 0);
    }

    Ok(())
}

#[test]
pub fn test_delegating_multisig() -> Result<(), ActorError> {
    let signer = Signer::new();
    let signer_arc = Arc::new(signer);
    let witness = {
        let witness_root = Builder::new().prefix("test-db").tempdir().unwrap();
        let path = witness_root.path();
        Witness::new(
            Url::parse("http://example.com").unwrap(),
            signer_arc,
            path,
            WitnessEscrowConfig::default(),
        )
        .unwrap()
    };

    let mut delegator_1 = setup_controller(&witness)?;
    let mut delegator_2 = setup_controller(&witness)?;

    let delegator1_kel = delegator_1
        .storage
        .get_kel_messages_with_receipts_all(delegator_1.prefix())?
        .unwrap()
        .into_iter()
        .map(|not| Message::Notice(not))
        .collect::<Vec<_>>();
    let delegator2_kel = delegator_2
        .storage
        .get_kel_messages_with_receipts_all(delegator_2.prefix())?
        .unwrap()
        .into_iter()
        .map(|not| Message::Notice(not))
        .collect::<Vec<_>>();

    delegator_1.process(&delegator2_kel)?;
    delegator_2.process(&delegator1_kel)?;

    // Make group of delegators
    let (group_icp, exchange_messages) = delegator_1.group_incept(
        vec![delegator_2.prefix().clone()],
        &SignatureThreshold::Simple(2),
        Some(vec![witness.prefix.clone()]),
        Some(1),
        None,
    )?;

    let delegator_group_id = group_icp.event_message.data.get_prefix();
    assert_eq!(exchange_messages.len(), 1);

    // Send exchange message from delegator 1 to delegator 2
    witness.process_exchange(exchange_messages[0].clone())?;

    // Delegator2 asks witness about his mailbox.
    let mbx_msg = delegator_2.query_mailbox(&witness.prefix);
    let response = witness.process_query(mbx_msg).unwrap();
    if let Some(PossibleResponse::Mbx(MailboxResponse {
        receipt: _,
        multisig,
        delegate: _,
    })) = response
    {
        assert_eq!(multisig.len(), 1);

        let group_icp_to_sign = multisig[0].clone();
        let exn_from_delegator2 = delegator_2.process_own_multisig(group_icp_to_sign)?;

        // Send signed icp event to other group participants.
        witness.process_exchange(exn_from_delegator2)?;
    };

    // Delegator1 asks witness about group mailbox to have fully signed dip.
    let mbx_msg = delegator_1.query_groups_mailbox(&witness.prefix);
    let response = witness.process_query(mbx_msg[0].clone()).unwrap();
    if let Some(PossibleResponse::Mbx(MailboxResponse {
        receipt: _,
        multisig,
        delegate: _,
    })) = response
    {
        assert_eq!(multisig.len(), 1);

        let group_icp = multisig[0].clone();
        // delegator1 is a leader, he will send fully signed event to witness
        let fully_signed_delegator_icp = delegator_1.process_group_multisig(group_icp.clone())?;
        witness.process_notice(Notice::Event(fully_signed_delegator_icp.unwrap()))?;
    };

    // Delegator2 didn't accept group dip yet because of lack of witness receipt.
    let state = delegator_2.get_state_for_id(&delegator_group_id);
    assert_eq!(state, None);
    // Also Delegator1 didn't accept it.
    let state = delegator_1.get_state_for_id(&delegator_group_id);
    assert_eq!(state, None);

    // Delegator ask about group mailbox to get receipt
    for delegator in vec![&delegator_1, &delegator_2] {
        let mbx_query = delegator.query_groups_mailbox(&witness.prefix);

        let response = witness.process_query(mbx_query[0].clone()).unwrap();
        if let Some(PossibleResponse::Mbx(MailboxResponse {
            receipt,
            multisig: _,
            delegate: _,
        })) = response
        {
            assert_eq!(receipt.len(), 1);
            delegator.process_receipt(receipt[0].clone())?;
        };
    }

    let state = delegator_2.get_state_for_id(&delegator_group_id);
    assert_eq!(state.unwrap().sn, 0);
    let state = delegator_1.get_state_for_id(&delegator_group_id);
    assert_eq!(state.unwrap().sn, 0);

    let delegator_kel = delegator_2
        .storage
        .get_kel_messages_with_receipts_all(&delegator_group_id)?
        .unwrap()
        .into_iter()
        .map(|not| Message::Notice(not))
        .collect::<Vec<_>>();

    // Child will create temporary identifier which can be used to send
    // delegation request to delegator. If it use delegated identifier, witness
    // won't be able to verify its delegation request event, because it won't be
    // confirmed at that point.
    let mut child = setup_controller(&witness)?;
    // Process delegator's kel
    child.process(&delegator_kel)?;

    // Make delegated inception event.
    // TODO it can return exn to delegator along with exn's to other group participants.
    let (dip, _) = child.group_incept(
        vec![],
        &SignatureThreshold::Simple(1),
        Some(vec![witness.prefix.clone()]),
        Some(1),
        Some(delegator_group_id.clone()),
    )?;

    // Request delegating confirmation
    let delegation_request =
        child.create_forward_message(&delegator_group_id, &dip, ForwardTopic::Delegate)?;

    let delegated_child_id = dip.event_message.data.get_prefix();
    let dip_digest = dip.event_message.digest()?;

    // Send delegation request to witness.
    witness.process_exchange(delegation_request)?;

    for delegator in [&delegator_1, &delegator_2] {
        // Delegators ask group mailbox for delegation request
        let mbx_msg = delegator.query_groups_mailbox(&witness.prefix);
        let response = witness.process_query(mbx_msg[0].clone()).unwrap();

        if let Some(PossibleResponse::Mbx(MailboxResponse {
            receipt: _,
            multisig: _,
            delegate,
        })) = response
        {
            assert_eq!(delegate.len(), 1);

            let dip_to_confirm = delegate[0].clone();
            let exn_ixn_multisig =
                delegator.process_group_delegate(dip_to_confirm, &delegator_group_id)?;

            // Send delegating event to other group participant, using witness's mailbox.
            witness.process_exchange(exn_ixn_multisig)?;

            // Delegating event still not accepted by witness.
            let state = witness
                .event_storage
                .get_state(&delegator_group_id)
                .unwrap();
            assert_eq!(state.sn, 0);
        };
    }

    // Delegator gets group mailbox
    let multisig_result = [&delegator_1, &delegator_2]
        .into_iter()
        .map(|delegator| -> Result<_, _> {
            let mbx_msg = delegator.query_groups_mailbox(&witness.prefix);
            let response = witness.process_query(mbx_msg[0].clone()).unwrap();
            if let Some(PossibleResponse::Mbx(MailboxResponse {
                receipt: _,
                multisig,
                delegate: _,
            })) = response
            {
                assert_eq!(multisig.len(), 3);

                let ixn_to_confirm = multisig[1].clone();
                let _signed_event = delegator.process_group_multisig(ixn_to_confirm)?;

                let ixn_to_confirm = multisig[2].clone();
                let signed_event = delegator.process_group_multisig(ixn_to_confirm)?;

                Ok(signed_event)
            } else {
                Ok(None)
            }
        })
        .collect::<Result<Vec<_>, Error>>()?;

    // Delegator1 is leader so he will return fully signed event.
    assert!(multisig_result[0].is_some());
    assert!(multisig_result[1].is_none());

    // Send it to witness
    let fully_signed_ixn = multisig_result[0].clone().unwrap();
    witness
        .process_notice(Notice::Event(fully_signed_ixn.clone()))
        .unwrap();

    // Collect witness receipts and send delegating event to child
    // Delegator ask about group mailbox to get receipts
    for delegator in vec![&delegator_1, &delegator_2] {
        let mbx_query = delegator.query_groups_mailbox(&witness.prefix);

        let response = witness.process_query(mbx_query[0].clone()).unwrap();
        if let Some(PossibleResponse::Mbx(MailboxResponse {
            receipt,
            multisig: _,
            delegate: _,
        })) = response
        {
            assert_eq!(receipt.len(), 2);
            delegator.process_receipt(receipt[1].clone())?;
        };
    }
    // Both delegators accepted delegating event
    let state = delegator_1.get_state_for_id(&delegator_group_id);
    assert_eq!(state.unwrap().sn, 1);
    let state = delegator_2.get_state_for_id(&delegator_group_id);
    assert_eq!(state.unwrap().sn, 1);

    // TODO add function for getting event with signatures and witness receipts
    let fully_witnessed_ixn = delegator_1
        .storage
        .get_kel_messages_with_receipts_all(&delegator_group_id)?
        .unwrap()
        .clone();

    // leader should collect signatures and receipts of ixn event
    let ixn_to_forward = if let Notice::Event(event) = fully_witnessed_ixn[1].clone() {
        event
    } else {
        unreachable!()
    };
    // let ixn_to_forward = if let Notice::NontransferableRct(rct) = fully_witnessed_ixn[2].clone() {
    //     let couplets = rct.signatures;
    //     // there is only one witness so index will be 0
    //     SignedEventMessage {
    //         witness_receipts: Some(couplets),
    //         ..fully_signed_ixn.clone()
    //     }
    // } else {
    //     unreachable!()
    // };

    let exn_to_child = delegator_1.create_forward_message(
        &delegated_child_id,
        &ixn_to_forward,
        ForwardTopic::Delegate,
    )?;
    witness.process_exchange(exn_to_child)?;

    // child get its mailbox
    // TODO for now delegated id is delegated group that has one
    // participant.
    let mbx_query = child.query_groups_mailbox(&witness.prefix);

    let response = witness.process_query(mbx_query[0].clone()).unwrap();
    if let Some(PossibleResponse::Mbx(MailboxResponse {
        receipt: _,
        multisig: _,
        delegate,
    })) = response
    {
        let msg = Message::Notice(Notice::Event(delegate[0].clone()));
        child.process(&[msg])?;
    };

    // Child has current delegator kel.
    let state = child.get_state_for_id(&delegator_group_id);
    assert_eq!(state.unwrap().sn, 1);

    // Delegated child event is not accepted bacause of missing witness receipts.
    let state = child.get_state_for_id(&delegated_child_id);
    assert_eq!(state, None);

    let confirmed_delegate_dip = child
        .not_fully_witnessed_escrow
        .get_event_by_sn_and_digest(0, &delegated_child_id, &dip_digest)
        .unwrap()
        .unwrap();

    // Child sends it to witness
    witness.process_notice(Notice::Event(confirmed_delegate_dip.clone()))?;
    let mbx_query = child.query_groups_mailbox(&witness.prefix);

    let response = witness.process_query(mbx_query[0].clone()).unwrap();
    if let Some(PossibleResponse::Mbx(MailboxResponse {
        receipt,
        multisig: _,
        delegate: _,
    })) = response
    {
        child.process_receipt(receipt[0].clone())?;
    };

    // Delegated child kel was accepted
    let state = child.get_state_for_id(&delegated_child_id);
    assert_eq!(state.unwrap().sn, 0);

    Ok(())
}
