#[cfg(feature = "wallet")]
use universal_wallet::prelude::UnlockedWallet;

#[cfg(test)]
use crate::{database::sled::SledEventDatabase, error::Error, keri::Keri};
use crate::{event_message::signed_event_message::Message, event_parsing::attachment};

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
            query_event::{QueryArgs, QueryEvent, SignedQuery},
            reply_event::ReplyRoute,
            QueryRoute
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
    let witness = Witness::new(witness_root.path(), signer_arc.clone().public_key())?;

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
    witness.process(&[Message::Event(alice_icp)])?;
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
        QueryRoute::Ksn,
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
    let query_message = Message::Query(SignedQuery::new(qry, bob_pref.to_owned(), vec![signature]));

    witness.process(&vec![query_message])?;

    let response = witness.respond(signer_arc.clone())?;
    // assert_eq!(response.len(), 1);
    match &response[0] {
        Message::Reply(rpy) => {
            if let ReplyRoute::Ksn(_id, ksn) = rpy.reply.get_route() {
                assert_eq!(&ksn.state, &alice.get_state().unwrap().unwrap())
            }
        },
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
        QueryRoute::Log,
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
    let query_message = Message::Query(SignedQuery::new(qry, bob_pref.to_owned(), vec![signature]));

    witness.process(&vec![query_message])?;

    let response = witness.respond(signer_arc.clone())?;
    
    let alice_kel = alice.storage.get_kel_messages(alice.prefix())?;
    assert_eq!(response, alice_kel.unwrap());

    Ok(())
}

#[cfg(feature = "query")]
#[test]
pub fn test_key_state_notice() -> Result<(), Error> {
    use crate::{
        keri::witness::Witness,
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
fn interop() -> Result<(), Error> {
    use crate::event_parsing::Attachment;
    let issuer_kel_str = br#"{"v":"KERI10JSON0001b7_","t":"icp","d":"Ew-o5dU5WjDrxDBK4b4HrF82_rYb6MX6xsegjq4n0Y7M","i":"Ew-o5dU5WjDrxDBK4b4HrF82_rYb6MX6xsegjq4n0Y7M","s":"0","kt":"1","k":["DruZ2ykSgEmw2EHm34wIiEGsUa_1QkYlsCAidBSzUkTU"],"nt":"1","n":["Eao8tZQinzilol20Ot-PPlVz6ta8C4z-NpDOeVs63U8s"],"bt":"3","b":["BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo","BuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw","Bgoq68HCmYNUDgOz4Skvlu306o_NY-NrYuKAVhk3Zh9c"],"c":[],"a":[]}-VBq-AABAA0EpZtBNLxOIncUDeLgwX3trvDXFA5adfjpUwb21M5HWwNuzBMFiMZQ9XqM5L2bFUVi6zXomcYuF-mR7CFpP8DQ-BADAAWUZOb17DTdCd2rOaWCf01ybl41U7BImalPLJtUEU-FLrZhDHls8iItGRQsFDYfqft_zOr8cNNdzUnD8hlSziBwABmUbyT6rzGLWk7SpuXGAj5pkSw3vHQZKQ1sSRKt6x4P13NMbZyoWPUYb10ftJlfXSyyBRQrc0_TFqfLTu_bXHCwACKPLkcCa_tZKalQzn3EgZd1e_xImWdVyzfYQmQvBpfJZFfg2c-sYIL3zl1WHpMQQ_iDmxLSmLSQ9jZ9WAjcmDCg-EAB0AAAAAAAAAAAAAAAAAAAAAAA1AAG2022-04-11T20c50c16d643400p00c00{"v":"KERI10JSON00013a_","t":"ixn","d":"Ek48ahzTIUA1ynJIiRd3H0WymilgqDbj8zZp4zzrad-w","i":"Ew-o5dU5WjDrxDBK4b4HrF82_rYb6MX6xsegjq4n0Y7M","s":"1","p":"Ew-o5dU5WjDrxDBK4b4HrF82_rYb6MX6xsegjq4n0Y7M","a":[{"i":"EoLNCdag8PlHpsIwzbwe7uVNcPE1mTr-e1o9nCIDPWgM","s":"0","d":"EoLNCdag8PlHpsIwzbwe7uVNcPE1mTr-e1o9nCIDPWgM"}]}-VBq-AABAAZZlCpwL0QwqF-eTuqEgfn95QV9S4ruh4wtxKQbf1-My60Nmysprv71y0tJGEHkMsUBRz0bf-JZsMKyZ3N8m7BQ-BADAA6ghW2PpLC0P9CxmW13G6AeZpHinH-_HtVOu2jWS7K08MYkDPrfghmkKXzdsMZ44RseUgPPty7ZEaAxZaj95bAgABKy0uBR3LGMwg51xjMZeVZcxlBs6uARz6quyl0t65BVrHX3vXgoFtzwJt7BUl8LXuMuoM9u4PQNv6yBhxg_XEDwACJe4TwVqtGy1fTDrfPxa14JabjsdRxAzZ90wz18-pt0IwG77CLHhi9vB5fF99-fgbYp2Zoa9ZVEI8pkU6iejcDg-EAB0AAAAAAAAAAAAAAAAAAAAAAQ1AAG2022-04-11T20c50c22d909900p00c00{"v":"KERI10JSON00013a_","t":"ixn","d":"EPYT0dEpoc_5QKIGnRYFRqpXHGpeYOhveJTmHoVC6LMU","i":"Ew-o5dU5WjDrxDBK4b4HrF82_rYb6MX6xsegjq4n0Y7M","s":"2","p":"Ek48ahzTIUA1ynJIiRd3H0WymilgqDbj8zZp4zzrad-w","a":[{"i":"EzSVC7-SuizvdVkpXmHQx5FhUElLjUOjCbgN81ymeWOE","s":"0","d":"EQ6RIFoVUDmmyuoMDMPPHDm14GtXaIf98j4AG2vNfZ1U"}]}-VBq-AABAAYycRM_VyvV2fKyHdUceMcK8ioVrBSixEFqY1nEO9eTZQ2NV8hrLc_ux9_sKn1p58kyZv5_y2NW3weEiqn-5KAA-BADAAQl22xz4Vzkkf14xsHMAOm0sDkuxYY8SAgJV-RwDDwdxhN4WPr-3Pi19x57rDJAE_VkyYwKloUuzB5Dekh-JzCQABk98CK_xwG52KFWt8IEUU-Crmf058ZJPB0dCffn-zjiNNgjv9xyGVs8seb0YGInwrB351JNu0sMHuEEgPJLKxAgACw556h2q5_BG6kPHAF1o9neMLDrZN_sCaJ-3slWWX-y8M3ddPN8Zp89R9A36t3m2rq-sbC5h_UDg5qdnrZ-ZxAw-EAB0AAAAAAAAAAAAAAAAAAAAAAg1AAG2022-04-11T20c50c23d726188p00c00"#;
    let holder_kel_str = br#"{"v":"KERI10JSON0001b7_","t":"icp","d":"EeWTHzoGK_dNn71CmJh-4iILvqHGXcqEoKGF4VUc6ZXI","i":"EeWTHzoGK_dNn71CmJh-4iILvqHGXcqEoKGF4VUc6ZXI","s":"0","kt":"1","k":["DaUjZzbtZLpCZUrRUqA0LZIC83_Gbsj2BHMEOe7ChMsc"],"nt":"1","n":["EKxpiBfmvUwo_H_YT9-PsPjTZysUgiRE_OFs_pwvM9RU"],"bt":"3","b":["BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo","BuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw","Bgoq68HCmYNUDgOz4Skvlu306o_NY-NrYuKAVhk3Zh9c"],"c":[],"a":[]}-VBq-AABAAPNPcy7cftbCQRZtBE4RAIrSKGUfLweG0UoBN4636GU4O2qHck8zgFblSDALJ5YRGjMZxAZZbhqGJLS43zsFaBw-BADAAei_IOwg71UvnTiY_Z8ewWJTpWAd9F2aBOQBC7QKLkLfGC62scI1rpc0mBeXE6GKoP0KWs5IpMSN_MsxatxkWCwABajaJSa6vSdGO834ci5QPuYeQBRBvIs31ZyYI2LigyYO-bQEqx3NR4ODUGonndBFT6e6CdZdtUkf4CyNEbMrQCAACEpMn2CQ7FrxBXVIPCkERvRr1o41AaJFw9RGqA-uAsvcXSlaJ8JHwnYcdvuHTigYAFHn8PTAqBl3kjLo5ZWehDA-EAB0AAAAAAAAAAAAAAAAAAAAAAA1AAG2022-04-11T20c50c18d709371p00c00"#;
    let _witness1 = br#"{"v":"KERI10JSON0000fd_","t":"icp","d":"Eie2UH5m4ti4QNAa4Yct8ISFVtHBNKjX7gJ0ZEc_IBIM","i":"Bgoq68HCmYNUDgOz4Skvlu306o_NY-NrYuKAVhk3Zh9c","s":"0","kt":"1","k":["Bgoq68HCmYNUDgOz4Skvlu306o_NY-NrYuKAVhk3Zh9c"],"nt":"0","n":[],"bt":"0","b":[],"c":[],"a":[]}-VAn-AABAAgMfAHPyZHqGvBMrASQ7j8LMelEVjZaUdtfdQJKjvayrXxdtF6ZpolH6WD2efVNStyWLCstgn1dVolzqN9Wf2Bw-EAB0AAAAAAAAAAAAAAAAAAAAAAA1AAG2022-04-11T20c50c12d027186p00c00"#;
    let _witness2 = br#"{"v":"KERI10JSON0000fd_","t":"icp","d":"Ez7jRMWuy9UWweIF3RkLHecF7yH2jGceWqQYMDhyEECU","i":"BuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw","s":"0","kt":"1","k":["BuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw"],"nt":"0","n":[],"bt":"0","b":[],"c":[],"a":[]}-VAn-AABAAtMr9S7-k6zJr7-nmI0R_uCR189M_a09b2bDGOMbyFCmI6CZd76wKULESRFcHqpKYMRaJzj6Nqghceh4dxT_zAw-EAB0AAAAAAAAAAAAAAAAAAAAAAA1AAG2022-04-11T20c50c11d949552p00c00"#;
    let _witness3 = br#"{"v":"KERI10JSON0000fd_","t":"icp","d":"Erch8-EoKKuPgwH_O90xzU44DIx-hi6Yq_0yC7PZG0RQ","i":"BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo","s":"0","kt":"1","k":["BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo"],"nt":"0","n":[],"bt":"0","b":[],"c":[],"a":[]}-VAn-AABAAet3jlqpjTnkIrUUu8MqDmJSejeOSsHnfhyLR9gUHOiemBX0FqDatVQzzisXcXSW3E9Bys4_Oj7OBoczLTSwUBA-EAB0AAAAAAAAAAAAAAAAAAAAAAA1AAG2022-04-11T20c50c11d870386p00c00"#;

    use tempfile::Builder;
    // Create test db and event processor.
    let root = Builder::new().prefix("test-db").tempdir().unwrap();
    let alice_db = Arc::new(SledEventDatabase::new(root.path()).unwrap());

    let alice_key_manager = Arc::new(Mutex::new({
        use crate::signer::CryptoBox;
        CryptoBox::new()?
    }));

    // Init controller.
    let controller = Keri::new(Arc::clone(&alice_db), Arc::clone(&alice_key_manager))?;

    controller.parse_and_process(issuer_kel_str)?;
    let state = controller
        .get_state_for_prefix(
            &"Ew-o5dU5WjDrxDBK4b4HrF82_rYb6MX6xsegjq4n0Y7M"
                .parse()
                .unwrap(),
        )
        .unwrap()
        .unwrap();

    assert_eq!(state.sn, 2);
    let pk = state.current.public_keys;

    assert_eq!(
        pk[0],
        "DruZ2ykSgEmw2EHm34wIiEGsUa_1QkYlsCAidBSzUkTU"
            .parse()
            .unwrap()
    );

    controller.parse_and_process(holder_kel_str)?;
    let pk = controller
        .get_state_for_prefix(
            &"EeWTHzoGK_dNn71CmJh-4iILvqHGXcqEoKGF4VUc6ZXI"
                .parse()
                .unwrap(),
        )
        .unwrap()
        .unwrap()
        .current
        .public_keys;

    assert_eq!(
        pk[0],
        "DaUjZzbtZLpCZUrRUqA0LZIC83_Gbsj2BHMEOe7ChMsc"
            .parse()
            .unwrap()
    );

    let credential = br#"{"v":"ACDC10JSON00019e_","d":"EzSVC7-SuizvdVkpXmHQx5FhUElLjUOjCbgN81ymeWOE","s":"EWCeT9zTxaZkaC_3-amV2JtG6oUxNA36sCC0P5MI7Buw","i":"Ew-o5dU5WjDrxDBK4b4HrF82_rYb6MX6xsegjq4n0Y7M","a":{"d":"EbFNz3vOMBbzp5xmYRd6rijvq08DCe07bOR-DA5fzO6g","i":"EeWTHzoGK_dNn71CmJh-4iILvqHGXcqEoKGF4VUc6ZXI","dt":"2022-04-11T20:50:23.722739+00:00","LEI":"5493001KJTIIGC8Y1R17"},"e":{},"ri":"EoLNCdag8PlHpsIwzbwe7uVNcPE1mTr-e1o9nCIDPWgM"}"#;
    let sign = br#"-FABEw-o5dU5WjDrxDBK4b4HrF82_rYb6MX6xsegjq4n0Y7M0AAAAAAAAAAAAAAAAAAAAAAAEw-o5dU5WjDrxDBK4b4HrF82_rYb6MX6xsegjq4n0Y7M-AABAAKcvAE-GzYu4_aboNjC0vNOcyHZkm5Vw9-oGGtpZJ8pNdzVEOWhnDpCWYIYBAMVvzkwowFVkriY3nCCiBAf8JDw"#;
    let sig = attachment::attachment(sign).unwrap().1;
    if let Attachment::SealSignaturesGroups(atts) = sig {
        let keys = atts.iter().map(|(seal, sigs)| {
            controller
                .storage
                .get_keys_at_event(&seal.prefix, seal.sn, &seal.event_digest)
                .unwrap()
                .unwrap()
                .verify(credential, &sigs)
                .unwrap()
        });
        println!("keys: {:?}", keys.collect::<Vec<_>>());
    };

    Ok(())
}
