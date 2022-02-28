#[cfg(feature = "wallet")]
use universal_wallet::prelude::UnlockedWallet;

use crate::event_message::signed_event_message::Message;
#[cfg(test)]
use crate::{database::sled::SledEventDatabase, error::Error, keri::Keri};

use std::sync::{Arc, Mutex};

#[test]
fn test_direct_mode() -> Result<(), Error> {
    use tempfile::Builder;

    // Create test db and event processor.
    let root = Builder::new().prefix("test-db").tempdir().unwrap();
    std::fs::create_dir_all(root.path()).unwrap();
    let db_alice = Arc::new(SledEventDatabase::new(root.path()).unwrap());

    // Create test db and event processor.
    let root = Builder::new().prefix("test-db").tempdir().unwrap();
    std::fs::create_dir_all(root.path()).unwrap();
    let db_bob = Arc::new(SledEventDatabase::new(root.path()).unwrap());

    let alice_key_manager = {
        #[cfg(feature = "wallet")]
        {
            let mut alice_key_manager = UnlockedWallet::new("alice");
            crate::signer::wallet::incept_keys(&mut alice_key_manager)?;
            Arc::new(Mutex::new(alice_key_manager))
        }
        #[cfg(not(feature = "wallet"))]
        {
            use crate::signer::CryptoBox;
            Arc::new(Mutex::new(CryptoBox::new()?))
        }
    };

    // Init alice.
    let mut alice = Keri::new(Arc::clone(&db_alice), alice_key_manager.clone())?;

    assert_eq!(alice.get_state()?, None);

    //lazy_static! {
    //  static ref BK: Arc<Mutex<dyn KeyManager>> = {
    let bob_key_manager = {
        #[cfg(feature = "wallet")]
        {
            let mut bob_key_manager = UnlockedWallet::new("alice");
            crate::signer::wallet::incept_keys(&mut bob_key_manager)?;
            Arc::new(Mutex::new(bob_key_manager))
        }
        #[cfg(not(feature = "wallet"))]
        {
            use crate::signer::CryptoBox;
            Arc::new(Mutex::new(CryptoBox::new().unwrap()))
        }
    };
    //}

    // Init bob.
    let mut bob = Keri::new(Arc::clone(&db_bob), bob_key_manager.clone())?;

    bob.incept(None, None).unwrap();
    let bob_state = bob.get_state()?;
    assert_eq!(bob_state.unwrap().sn, 0);

    // Get alice's inception event.
    let alice_incepted = alice.incept(None, None)?;
    let msg_to_bob = vec![Message::Event(alice_incepted)];

    // Send it to bob.
    bob.process(&msg_to_bob)?;
    let msg_to_alice = bob.respond()?;

    // Check response
    let mut events_in_response = msg_to_alice.clone().into_iter();
    assert!(matches!(events_in_response.next(), Some(Message::Event(_))));
    assert!(matches!(
        events_in_response.next(),
        Some(Message::TransferableRct(_))
    ));

    // Check if bob's state of alice is the same as current alice state.
    let alice_state_in_bob = bob.get_state_for_prefix(&alice.prefix)?.unwrap();
    assert_eq!(alice_state_in_bob, alice.get_state()?.unwrap());

    // Send message from bob to alice and get alice's receipts.
    alice.process(&msg_to_alice)?;
    let msg_to_bob = alice.respond()?;

    // Check response. It should be transferable receipt message from alice.
    let mut events_in_response = msg_to_bob.iter();
    assert!(matches!(
        events_in_response.next(),
        Some(Message::TransferableRct(_))
    ));

    // Check if alice's state of bob is the same as current bob state.
    let bob_state_in_alice = alice.get_state_for_prefix(&bob.prefix)?.unwrap();
    assert_eq!(bob_state_in_alice, bob.get_state()?.unwrap());

    // Send it to bob.
    bob.process(&msg_to_bob)?;
    let bobs_res = bob.respond()?;

    assert!(bobs_res.is_empty());

    // Rotation event.
    let alice_rot = alice.rotate(None, None, None)?;
    assert_eq!(alice.get_state()?.unwrap().sn, 1);

    // Send rotation event to bob.
    let msg_to_bob = alice_rot.serialize()?;
    bob.parse_and_process(&msg_to_bob)?;
    let msg_to_alice = bob.respond()?;

    // Check response. It should be transferable receipt message from bob.
    let mut events_in_response = msg_to_alice.iter();
    assert!(matches!(
        events_in_response.next(),
        Some(Message::TransferableRct(_))
    ));

    // Check if bob's state of alice is the same as current alice state.
    let alice_state_in_bob = bob.get_state_for_prefix(&alice.prefix)?.unwrap();
    assert_eq!(alice_state_in_bob, alice.get_state()?.unwrap());

    // Send bob's receipt to alice.
    alice.process(&msg_to_alice)?;
    let alice_res = alice.respond()?;
    assert!(alice_res.is_empty());

    // Interaction event.
    let alice_ixn = alice.make_ixn(None)?;
    assert_eq!(alice.get_state()?.unwrap().sn, 2);

    // Send interaction event to bob.
    let msg_to_bob = alice_ixn.serialize()?;
    bob.parse_and_process(&msg_to_bob)?;
    let msg_to_alice = bob.respond()?;

    // Check response. It should be trnasferable receipt message from bob.
    let mut events_in_response = msg_to_alice.iter();
    assert!(matches!(
        events_in_response.next(),
        Some(Message::TransferableRct(_))
    ));

    // Check if bob's state of alice is the same as current alice state.
    let alice_state_in_bob = bob.get_state_for_prefix(&alice.prefix)?.unwrap();
    assert_eq!(alice_state_in_bob, alice.get_state()?.unwrap());

    alice.process(&msg_to_alice)?;
    alice.respond()?;

    Ok(())
}

#[cfg(feature = "query")]
#[test]
fn test_qry_rpy() -> Result<(), Error> {
    use tempfile::Builder;

    use crate::{
        derivation::{self_addressing::SelfAddressing, self_signing::SelfSigning},
        event::SerializationFormats,
        keri::witness::Witness,
        prefix::AttachedSignaturePrefix,
        query::{
            query::{QueryArgs, QueryEvent, SignedQuery},
            ReplyType, Route,
        },
        signer::KeyManager,
    };

    // Create test db and event processor.
    let root = Builder::new().prefix("test-db").tempdir().unwrap();
    let alice_db = Arc::new(SledEventDatabase::new(root.path()).unwrap());
    let root = Builder::new().prefix("test-db").tempdir().unwrap();
    let bob_db = Arc::new(SledEventDatabase::new(root.path()).unwrap());

    let witness_root = Builder::new().prefix("test-db").tempdir().unwrap();
    let witness = Witness::new(witness_root.path())?;

    let alice_key_manager = Arc::new(Mutex::new({
        use crate::signer::CryptoBox;
        CryptoBox::new()?
    }));

    // Init alice.
    let mut alice = Keri::new(Arc::clone(&alice_db), Arc::clone(&alice_key_manager))?;

    let bob_key_manager = Arc::new(Mutex::new({
        use crate::signer::CryptoBox;
        CryptoBox::new()?
    }));

    // Init bob.
    let mut bob = Keri::new(Arc::clone(&bob_db), Arc::clone(&bob_key_manager))?;

    let bob_icp = bob.incept(None, None).unwrap();
    // bob.rotate().unwrap();

    let bob_pref = bob.prefix();

    let alice_icp = alice.incept(Some(vec![witness.prefix.clone()]), None)?;
    // send alices icp to witness
    let _rcps = witness.process(&[Message::Event(alice_icp)])?;
    // send bobs icp to witness to have his keys
    let _rcps = witness.process(&[Message::Event(bob_icp)])?;

    let query_args = QueryArgs {
        s: None,
        i: alice.prefix().clone(),
        src: None,
    };

    // Bob asks about alices key state
    // construct qry message to ask of alice key state message
    let qry = QueryEvent::new_query(
        Route::Ksn,
        query_args,
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
    let s = SignedQuery::new(qry, bob_pref.to_owned(), vec![signature]);

    // ask witness about alice's key state notice
    let rep = witness.process_signed_query(s)?;

    match rep {
        ReplyType::Rep(rep) => {
            assert_eq!(
                &rep.reply.event.get_state(),
                &alice.get_state().unwrap().unwrap()
            )
        }
        ReplyType::Kel(_) => assert!(false),
    }

    Ok(())
}

#[cfg(feature = "query")]
#[test]
pub fn test_key_state_notice() -> Result<(), Error> {
    use crate::{
        keri::witness::Witness,
        processor::{notification::Notification, EventProcessor},
        query::QueryError,
        signer::CryptoBox,
    };
    use tempfile::Builder;

    let witness = {
        let witness_root = Builder::new().prefix("test-db").tempdir().unwrap();
        let path = witness_root.path();
        std::fs::create_dir_all(path).unwrap();
        Witness::new(path)?
    };

    // Init bob.
    let mut bob = {
        // Create test db and event processor.
        let root = Builder::new().prefix("test-db").tempdir().unwrap();
        std::fs::create_dir_all(root.path()).unwrap();
        let db = Arc::new(SledEventDatabase::new(root.path()).unwrap());

        let bob_key_manager = Arc::new(Mutex::new(CryptoBox::new()?));
        Keri::new(Arc::clone(&db), Arc::clone(&bob_key_manager))?
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
    let signed_rpy = witness.get_ksn_for_prefix(&bob_pref)?;

    // Process reply message before having any bob's events in db.
    let res = alice_processor.process(Message::KeyStateNotice(signed_rpy.clone()));
    assert!(matches!(res, Ok(Notification::KsnOutOfOrder(_))));
    alice_processor.process(Message::Event(bob_icp))?;

    // rotate bob's keys. Let alice process his rotation. She will have most recent bob's event.
    let bob_rot = bob.rotate(None, None, None)?;
    witness.process(&[Message::Event(bob_rot.clone())])?;
    alice_processor.process(Message::Event(bob_rot.clone()))?;

    // try to process old reply message
    let res = alice_processor.process(Message::KeyStateNotice(signed_rpy.clone()));
    assert!(matches!(res, Err(Error::QueryError(QueryError::StaleKsn))));

    // now create new reply event by witness and process it by alice.
    let new_reply = witness.get_ksn_for_prefix(&bob_pref)?;
    let res = alice_processor.process(Message::KeyStateNotice(new_reply.clone()));
    assert!(res.is_ok());

    let new_bob_rot = bob.rotate(None, None, None)?;
    witness.process(&[Message::Event(new_bob_rot.clone())])?;
    // Create transferable reply by bob and process it by alice.
    let trans_rpy = witness.get_ksn_for_prefix(&bob_pref)?;
    let res = alice_processor.process(Message::KeyStateNotice(trans_rpy.clone()));
    assert!(matches!(res, Ok(Notification::KsnOutOfOrder(_))));

    // Now update bob's state in alice's db to most recent.
    alice_processor.process(Message::Event(new_bob_rot))?;
    let res = alice_processor.process(Message::KeyStateNotice(trans_rpy.clone()));
    assert_eq!(res?, Notification::ReplyUpdated);

    Ok(())
}
