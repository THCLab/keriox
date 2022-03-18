use crate::event_message::signed_event_message::Message;
use crate::event_parsing::message::{signed_event_stream, signed_message};
use crate::prefix::IdentifierPrefix;
use crate::processor::escrow::default_escrow_bus;
use crate::processor::event_storage::EventStorage;
use crate::processor::notification::Notification;
use crate::processor::EventProcessor;
use crate::{database::sled::SledEventDatabase, error::Error};
use std::convert::TryFrom;
use std::fs;
use std::sync::Arc;

#[test]
fn test_process() -> Result<(), Error> {
    use tempfile::Builder;

    // Create test db and event processor.
    let root = Builder::new().prefix("test-db").tempdir().unwrap();
    fs::create_dir_all(root.path()).unwrap();

    let db = Arc::new(SledEventDatabase::new(root.path()).unwrap());
    let event_processor = EventProcessor::new(Arc::clone(&db));
    let event_storage = EventStorage::new(Arc::clone(&db));
    // Events and sigs are from keripy `test_multisig_digprefix` test.
    // (keripy/tests/core/test_eventing.py#1138)

    let icp_raw = br#"{"v":"KERI10JSON0001e7_","t":"icp","d":"EZrJQSdhdiyXNpEzHo-dR0EEbLfcIopBSImdLnQGOKkg","i":"EZrJQSdhdiyXNpEzHo-dR0EEbLfcIopBSImdLnQGOKkg","s":"0","kt":"2","k":["DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA","DVcuJOOJF1IE8svqEtrSuyQjGTd2HhfAkt9y2QkUtFJI","DT1iAhBWCkvChxNWsby2J0pJyxBIxbAtbLA0Ljx-Grh8"],"nt":"2","n":["E_IkdcjsIFrFba-LS1sJDjpec_4vM3XtIPa6D51GcUIw","EU28GjHFKeXzncPxgwlHQZ0iO7f09Y89vy-3VkZ23bBI","E2PRzip7UZ5UTA_1ucb5eoAzxeRS3sIThrSbZhdRaZY8"],"bt":"0","b":[],"c":[],"a":[]}-AADAAzclB26m4VWp5R8ANlTU2qhqE6GA9siAK_vhtqtNNR6qhVed-xEoXRadnL5Jc0kxPZi8XUqSk5KSaOnke_SxXDAABX--x4JGI0Dp0Ran-t1LMg3NEgizu1Jb85LTImofYqD6jz9w5TTPNAmj7rfIFvd4mfJ_ioH0Z0mzLWuIvTIFCBAACQTiHacY3flY9y_Wup66bNzcyQvJUT-WGkv4CPgqkMwq5mOEFf2ps74bur1AE9OSGgrEBlcOQ9HWuTcr80FMKCg"#;
    let parsed = signed_message(icp_raw).unwrap().1;
    let deserialized_icp = Message::try_from(parsed).unwrap();

    let id = match &deserialized_icp {
        Message::Event(e) => e.event_message.event.get_prefix(),
        _ => Err(Error::SemanticError("bad deser".into()))?,
    };

    // Process icp event.
    event_processor.process(deserialized_icp)?;

    // Check if processed event is in kel.
    let icp_from_db = event_storage.get_event_at_sn(&id, 0).unwrap();
    let re_serialized = icp_from_db
        .unwrap()
        .signed_event_message
        .serialize()
        .unwrap();
    assert_eq!(icp_raw.to_vec(), re_serialized);

    let rot_raw = br#"{"v":"KERI10JSON00021c_","t":"rot","d":"EcR5L1yzQeSOFBdFwmWouiEMzCFC6GhJ28Q2RWta4GxQ","i":"EZrJQSdhdiyXNpEzHo-dR0EEbLfcIopBSImdLnQGOKkg","s":"1","p":"EZrJQSdhdiyXNpEzHo-dR0EEbLfcIopBSImdLnQGOKkg","kt":"2","k":["DKPE5eeJRzkRTMOoRGVd2m18o8fLqM2j9kaxLhV3x8AQ","D1kcBE7h0ImWW6_Sp7MQxGYSshZZz6XM7OiUE5DXm0dU","D4JDgo3WNSUpt-NG14Ni31_GCmrU0r38yo7kgDuyGkQM"],"nt":"2","n":["E2PRzip7UZ5UTA_1ucb5eoAzxeRS3sIThrSbZhdRaZY8","Ea450np2ffBYk-mkVaxPk9h17OykLKqEkGrBFKomwe1A","EcNDEzyAJJsUOCa2YIBE3N-8KtpsZBShxxXhddAGVFko"],"bt":"0","br":[],"ba":[],"a":[]}-AADAAZte0g5dCVxAD4qxbBf-Y8uLqMu-4NlrqoVi1FR2JxmZuHAXU-8BUhEJ7z8nxPycvTBJW7kXR30Wyk19GVm-fBwAB8NydT0xIWiYLPuavDpzlZZrYVF_nFgBgf-joxH0FSmyTuDEDhwz9H6b0EY47PhQeJ6cy6PtH8AXK_HVZ2yojDwACeHxfXD8MNjnqjkl0JmpFHNwlif7V0_DjUx3VHkGjDcMfW2bCt16jRW0Sefh45sb4ZXHfMNZ1vmwhPv1L5lNGDA"#;
    let parsed = signed_message(rot_raw).unwrap().1;
    let deserialized_rot = Message::try_from(parsed).unwrap();

    // Process rotation event.
    event_processor.process(deserialized_rot.clone())?;
    let rot_from_db = event_storage.get_event_at_sn(&id, 1).unwrap().unwrap();
    assert_eq!(
        rot_from_db.signed_event_message.serialize().unwrap(),
        rot_raw
    );

    // Process the same rotation event one more time.
    let notification = event_processor.process(deserialized_rot);
    assert!(matches!(notification, Ok(Notification::DupliciousEvent(_))));

    let ixn_raw = br#"{"v":"KERI10JSON0000cb_","t":"ixn","d":"EA7xKzFFmrQAsu9nOQdePCotb4JLJ7kjHa4k0jQpKjIc","i":"EZrJQSdhdiyXNpEzHo-dR0EEbLfcIopBSImdLnQGOKkg","s":"2","p":"EcR5L1yzQeSOFBdFwmWouiEMzCFC6GhJ28Q2RWta4GxQ","a":[]}-AADAAqLhb_9rU6SYXUm55ZtQOtsY74YfgnLI5xQe8X8hKHgGd1LtLzfFezC9DaFLdz7vpUWWsGEXTs8MqCqfwLVM3BQABrP60M2UVdiZ3T741teIWhjivDxyKUWH9OfX1Sn85O_6Q3qKiipjByGlEZF6WM-FqftKmmtEKH7Uk_bmO2ed-BwAClhKT2EzzOy0oeVNdte3M6knIkaq49Ug-fpin18ey89rDWrg4KApCCpt9mbX2_Hvw5Fy_IuGECmdEVyLJ-XA7Bg"#;
    let parsed = signed_message(ixn_raw).unwrap().1;
    let deserialized_ixn = Message::try_from(parsed).unwrap();

    // Process interaction event.
    event_processor.process(deserialized_ixn.clone())?;

    // Check if processed event is in db.
    let ixn_from_db = event_storage.get_event_at_sn(&id, 2).unwrap().unwrap();
    match deserialized_ixn {
        Message::Event(evt) => assert_eq!(
            ixn_from_db.signed_event_message.event_message.event,
            evt.event_message.event
        ),
        _ => assert!(false),
    }

    // Construct partially signed interaction event.
    let ixn_raw_2 = br#"{"v":"KERI10JSON0000cb_","t":"ixn","d":"E8Megu9lmfm1o94jBXuhZHL_khCVrn5Bc5_kmc_dNck4","i":"EZrJQSdhdiyXNpEzHo-dR0EEbLfcIopBSImdLnQGOKkg","s":"3","p":"EA7xKzFFmrQAsu9nOQdePCotb4JLJ7kjHa4k0jQpKjIc","a":[]}-AADAAkRvfRJrjSY63l9_4uOejO1wCTxYPn_fVzGdCqQbVpFFhiGnjxXYs2wi_V4XIIk1ObXkoCwmR39WLsudeFw3bCQAB1mjHo3foYK-qBk_YIAq0xdU_HQYr9Ac46bDe8flOHiHIZsGyUXFHaBW-05F9PM0ejQYoTvZQ7KWkKUMcsWavAAACqP7gKQHCq-dHFo8vOriLF50o-m8DCnBpY1rCn6WvqTo83njoqNYd-l_cckXmISuDbYAFex3qoYY2s04g6V4ZDQ"#;
    let parsed = signed_message(ixn_raw_2).unwrap().1;
    let deserialized_ixn = Message::try_from(parsed).unwrap();
    // Make event partially signed.
    let partially_signed_deserialized_ixn = match deserialized_ixn {
        Message::Event(mut e) => {
            let sigs = e.signatures[1].clone();
            e.signatures = vec![sigs];
            Message::Event(e)
        }
        _ => Err(Error::SemanticError("bad deser".into()))?,
    };

    // Process partially signed interaction event.
    let notification = event_processor.process(partially_signed_deserialized_ixn);
    assert!(matches!(notification, Ok(Notification::PartiallySigned(_))));

    // Check if processed ixn event is in kel. It shouldn't because of not enough signatures.
    let ixn_from_db = event_storage.get_event_at_sn(&id, 3);
    assert!(matches!(ixn_from_db, Ok(None)));

    // // Out of order event.
    let out_of_order_rot_raw = br#"{"v":"KERI10JSON000190_","t":"rot","d":"EZPbvFYRgYz5QBGTgV05eJhngeUGUnFQs8sRWyD8hao0","i":"EZrJQSdhdiyXNpEzHo-dR0EEbLfcIopBSImdLnQGOKkg","s":"4","p":"E8Megu9lmfm1o94jBXuhZHL_khCVrn5Bc5_kmc_dNck4","kt":"2","k":["D4JDgo3WNSUpt-NG14Ni31_GCmrU0r38yo7kgDuyGkQM","DVjWcaNX2gCkHOjk6rkmqPBCxkRCqwIJ-3OjdYmMwxf4","DT1nEDepd6CSAMCE7NY_jlLdG6_mKUlKS_mW-2HJY1hg"],"nt":"0","n":[],"bt":"0","br":[],"ba":[],"a":[]}-AADAAVnoy6-LOPD5YN6yNFrQ1qekdi5RfihxDfZvBfoXunke8bVG9WKG6WVVoWLQRvPNq2LbOohPXN8mHaFue_i2fAgAB31vF_2rZnUUhzphg7dhD6PmuAexG9sgTfSv0Jf_y8DKxD3gMkDDnG78ramDa06kIjil5NcoulHKqUhybQRkkDwACDvEQck1y_W-0MMM04bIeXBvmbbYmH1Yd97psuRCLmFk2vHE0hGJ0v0o4HtRZY5Bm8L2Oqr3YCEOr-Li1ls1vCA"#;
    let parsed = signed_message(out_of_order_rot_raw).unwrap().1;
    let out_of_order_rot = Message::try_from(parsed).unwrap();

    let notification = event_processor.process(out_of_order_rot);
    assert!(matches!(notification, Ok(Notification::OutOfOrder(_))));

    // Check if processed event is in kel. It shouldn't.
    let raw_from_db = event_storage.get_event_at_sn(&id, 4);
    assert!(matches!(raw_from_db, Ok(None)));

    let id: IdentifierPrefix = "EZrJQSdhdiyXNpEzHo-dR0EEbLfcIopBSImdLnQGOKkg".parse()?;
    let mut kel = Vec::new();
    kel.extend(icp_raw);
    kel.extend(rot_raw);
    kel.extend(ixn_raw);

    let db_kel = event_storage.get_kel(&id)?;

    assert_eq!(db_kel, Some(kel));

    Ok(())
}

#[test]
fn test_process_receipt() -> Result<(), Error> {
    use tempfile::Builder;

    // Create test db and event processor.
    let root = Builder::new().prefix("test-db").tempdir().unwrap();
    fs::create_dir_all(root.path()).unwrap();
    let db = Arc::new(SledEventDatabase::new(root.path()).unwrap());
    let event_processor = EventProcessor::new(Arc::clone(&db));

    // Events and sigs are from keripy `test_direct_mode` test.
    // (keripy/tests/core/test_eventing.py)
    // Parse and process controller's inception event.
    let icp_raw = br#"{"v":"KERI10JSON00012b_","t":"icp","d":"EdwS_D6wppLqfIp5LSgly8GTScg5OWBaa7thzEnBqHvw","i":"EdwS_D6wppLqfIp5LSgly8GTScg5OWBaa7thzEnBqHvw","s":"0","kt":"1","k":["DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA"],"nt":"1","n":["E67B6WkwQrEfSA2MylxmF28HJc_HxfHRyK1kRXSYeMiI"],"bt":"0","b":[],"c":[],"a":[]}-AABAAEtmk7qXsdCpK8UhruVzPpIITUg4UPodQuzNsR29tUIT1sCWnjXOEVUC_mlYrgquYSZSE1Xq8r9OOlI3ELJEMAw"#;
    let parsed = signed_message(icp_raw).unwrap().1;
    let icp = Message::try_from(parsed).unwrap();
    let controller_id =
        "EsZuhYAPBDnexP3SOl9YsGvWBrYkjYcRjomUYmCcLAYY".parse::<IdentifierPrefix>()?;

    let notification = event_processor.process(icp)?;
    assert!(matches!(notification, Notification::KeyEventAdded(_)));

    let controller_id_state = EventStorage::new(db.clone()).get_state(&controller_id);

    // Parse receipt of controller's inception event.
    let vrc_raw = br#"{"v":"KERI10JSON000091_","t":"rct","d":"EdwS_D6wppLqfIp5LSgly8GTScg5OWBaa7thzEnBqHvw","i":"EdwS_D6wppLqfIp5LSgly8GTScg5OWBaa7thzEnBqHvw","s":"0"}-FABE0VtKUgXnnXq9EtfgKAd_l5lhyhx_Rlf0Uj1XejaNNoo0AAAAAAAAAAAAAAAAAAAAAAAE0VtKUgXnnXq9EtfgKAd_l5lhyhx_Rlf0Uj1XejaNNoo-AABAAhqa4qdyKUYl0gphqZp9511p3NfDecpUMvedi7pPxIVnufTeg3NpQ77GD9FNHTTtXZnQkZ2r8j_1-Iqi7ZMPlBg"#;
    let parsed = signed_message(vrc_raw).unwrap().1;
    let rcp = Message::try_from(parsed).unwrap();

    let notification = event_processor.process(rcp.clone());
    // Validator not yet in db. Event should be escrowed.
    assert!(matches!(
        notification,
        Ok(Notification::TransReceiptOutOfOrder(_))
    ));

    // Parse and process validator's inception event.
    let val_icp_raw = br#"{"v":"KERI10JSON00012b_","t":"icp","d":"E0VtKUgXnnXq9EtfgKAd_l5lhyhx_Rlf0Uj1XejaNNoo","i":"E0VtKUgXnnXq9EtfgKAd_l5lhyhx_Rlf0Uj1XejaNNoo","s":"0","kt":"1","k":["D8KY1sKmgyjAiUDdUBPNPyrSz_ad_Qf9yzhDNZlEKiMc"],"nt":"1","n":["E71sZjtEedBeNrGYRXmeTdmgbCJUTpXX5TW-VpNxxRXk"],"bt":"0","b":[],"c":[],"a":[]}-AABAAxXn_f_GuWg9ON12x59DXir636vEsdwAozFRDcLgx_TmTY8WuhRbW_zWAEFX7d_YYMtYNNVk7uoxp7s5U8m4FDA"#;
    let parsed = signed_message(val_icp_raw).unwrap().1;
    let val_icp = Message::try_from(parsed).unwrap();

    let notification = event_processor.process(val_icp)?;
    assert!(matches!(notification, Notification::KeyEventAdded(_)));

    // Process receipt once again.
    let notification = event_processor.process(rcp)?;
    assert!(matches!(notification, Notification::ReceiptAccepted));

    let id_state = EventStorage::new(db.clone()).get_state(&controller_id);
    // Controller's state shouldn't change after processing receipt.
    assert_eq!(controller_id_state?, id_state?);

    Ok(())
}
#[test]
fn test_process_delegated() -> Result<(), Error> {
    use tempfile::Builder;
    // Create test db and event processor.
    let root = Builder::new().prefix("test-db").tempdir().unwrap();
    fs::create_dir_all(root.path()).unwrap();
    let db = Arc::new(SledEventDatabase::new(root.path()).unwrap());
    let event_processor = EventProcessor::new(Arc::clone(&db));
    let event_storage = EventStorage::new(Arc::clone(&db));

    // Events and sigs are from keripy `test_delegation` test.
    // (keripy/tests/core/test_delegating.py)
    let bobs_pref: IdentifierPrefix = "E7YbTIkWWyNwOxZQTTnrs6qn8jFbu2A8zftQ33JYQFQ0".parse()?;

    let bobs_icp = br#"{"v":"KERI10JSON00012b_","t":"icp","d":"E7YbTIkWWyNwOxZQTTnrs6qn8jFbu2A8zftQ33JYQFQ0","i":"E7YbTIkWWyNwOxZQTTnrs6qn8jFbu2A8zftQ33JYQFQ0","s":"0","kt":"1","k":["DqI2cOZ06RwGNwCovYUWExmdKU983IasmUKMmZflvWdQ"],"nt":"1","n":["EOmBSdblll8qB4324PEmETrFN-DhElyZ0BcBH1q1qukw"],"bt":"0","b":[],"c":[],"a":[]}-AABAAotHSmS5LuCg2LXwlandbAs3MFR0yTC5BbE2iSW_35U2qA0hP9gp66G--mHhiFmfHEIbBKrs3tjcc8ySvYcpiBg"#;
    let parsed = signed_message(bobs_icp).unwrap().1;
    let msg = Message::try_from(parsed).unwrap();
    event_processor.process(msg)?;

    // Delegated inception event.
    let dip_raw = br#"{"v":"KERI10JSON00015f_","t":"dip","d":"ESVGDRnpHMCAESkvj2bxKGAmMloX6K6vxfcmBLTOCM0A","i":"ESVGDRnpHMCAESkvj2bxKGAmMloX6K6vxfcmBLTOCM0A","s":"0","kt":"1","k":["DuK1x8ydpucu3480Jpd1XBfjnCwb3dZ3x5b1CJmuUphA"],"nt":"1","n":["Ej1L6zmDszZ8GmBdYGeUYmAwoT90h3Dt9kRAS90nRyqI"],"bt":"0","b":[],"c":[],"a":[],"di":"E7YbTIkWWyNwOxZQTTnrs6qn8jFbu2A8zftQ33JYQFQ0"}-AABAAbb1dks4dZCRcibL74840WKKtk9wsdMLLlmNFkjb1s7hBfevCqpN8nkZaewQFZu5QWR-rbZtN-Y8DDQ8lh_1WDA-GAB0AAAAAAAAAAAAAAAAAAAAAAQE4ncGiiaG9wbKMHrACX9iPxb7fMSSeBSnngBNIRoZ2_A"#;
    let parsed = signed_message(dip_raw).unwrap().1;
    let deserialized_dip = Message::try_from(parsed).unwrap();

    // Process dip event before delegating ixn event.
    let notification = event_processor.process(deserialized_dip.clone());
    assert!(matches!(notification, Ok(Notification::OutOfOrder(_))));

    let child_prefix: IdentifierPrefix = "ESVGDRnpHMCAESkvj2bxKGAmMloX6K6vxfcmBLTOCM0A".parse()?;

    // Check if processed dip is in kel.
    let dip_from_db = event_storage.get_event_at_sn(&child_prefix, 0);
    assert!(matches!(dip_from_db, Ok(None)));

    // Bob's ixn event with delegating event seal.
    let bobs_ixn = br#"{"v":"KERI10JSON00013a_","t":"ixn","d":"E4ncGiiaG9wbKMHrACX9iPxb7fMSSeBSnngBNIRoZ2_A","i":"E7YbTIkWWyNwOxZQTTnrs6qn8jFbu2A8zftQ33JYQFQ0","s":"1","p":"E7YbTIkWWyNwOxZQTTnrs6qn8jFbu2A8zftQ33JYQFQ0","a":[{"i":"ESVGDRnpHMCAESkvj2bxKGAmMloX6K6vxfcmBLTOCM0A","s":"0","d":"ESVGDRnpHMCAESkvj2bxKGAmMloX6K6vxfcmBLTOCM0A"}]}-AABAARpc88hIeWV9Z2IvzDl7dRHP-g1-EOYZLiDKyjNZB9PDSeGcNTj_SUXgWIVNdssPL7ajYvglbvxRwIU8teoFHCA"#;
    let parsed = signed_message(bobs_ixn).unwrap().1;
    let deserialized_ixn = Message::try_from(parsed).unwrap();
    event_processor.process(deserialized_ixn.clone())?;

    let raw_parsed = |ev: Message| -> Result<Vec<_>, Error> {
        if let Message::Event(ev) = ev {
            ev.event_message.serialize()
        } else {
            Ok(vec![])
        }
    };

    // Check if processed event is in db.
    let ixn_from_db = event_storage
        .get_event_at_sn(&bobs_pref, 1)
        .unwrap()
        .unwrap();
    assert_eq!(
        ixn_from_db.signed_event_message.event_message.serialize()?,
        raw_parsed(deserialized_ixn)?
    );

    // Process delegated inception event once again.
    event_processor.process(deserialized_dip.clone())?;

    // Check if processed dip event is in db.
    let dip_from_db = event_storage.get_event_at_sn(&child_prefix, 0)?.unwrap();

    assert_eq!(
        dip_from_db.signed_event_message.event_message.serialize()?,
        raw_parsed(deserialized_dip.clone())?
    );

    // Bobs interaction event with delegated event seal.
    let bob_ixn = br#"{"v":"KERI10JSON00013a_","t":"ixn","d":"EAh9mAkWlONIqJPdhMFQ4a9jx4nZWz7JW6wLp9T2YFqk","i":"E7YbTIkWWyNwOxZQTTnrs6qn8jFbu2A8zftQ33JYQFQ0","s":"2","p":"E4ncGiiaG9wbKMHrACX9iPxb7fMSSeBSnngBNIRoZ2_A","a":[{"i":"ESVGDRnpHMCAESkvj2bxKGAmMloX6K6vxfcmBLTOCM0A","s":"1","d":"EnjU4Rc4YtHFV7ezc6FbmXWNdT4QGE2sTtl-yaGXH-ag"}]}-AABAAEGO3wl32as1yxubkrY19x_BwntHVl7jAXHhUpFEPkkpkBxA9lbIG_vhe6-gm-GT6pwKg_pfPDr7pWTZ5sgR5AQ"#;
    let parsed = signed_message(bob_ixn).unwrap().1;
    let deserialized_ixn_drt = Message::try_from(parsed).unwrap();

    // Delegated rotation event.
    let drt_raw = br#"{"v":"KERI10JSON000160_","t":"drt","d":"EnjU4Rc4YtHFV7ezc6FbmXWNdT4QGE2sTtl-yaGXH-ag","i":"ESVGDRnpHMCAESkvj2bxKGAmMloX6K6vxfcmBLTOCM0A","s":"1","p":"ESVGDRnpHMCAESkvj2bxKGAmMloX6K6vxfcmBLTOCM0A","kt":"1","k":["DTf6QZWoet154o9wvzeMuNhLQRr8JaAUeiC6wjB_4_08"],"nt":"1","n":["EJHd79BFLgnljYhhWP2wmc6RD3A12oHDJhkixwNe2sH0"],"bt":"0","br":[],"ba":[],"a":[]}-AABAA9-6k6bExTqgFDG8akEA7ifbMPxsWDe0ttdAXpm3HiYdjfTlY5-vUcDZ1e6RHs6xLADNiNhmKHAuRQW8nmFyPBw-GAB0AAAAAAAAAAAAAAAAAAAAAAgEAh9mAkWlONIqJPdhMFQ4a9jx4nZWz7JW6wLp9T2YFqk"#;
    let parsed = signed_message(drt_raw).unwrap().1;
    let deserialized_drt = Message::try_from(parsed).unwrap();

    // Process drt event before delegating ixn event.
    let child_notification = event_processor.process(deserialized_drt.clone());
    assert!(matches!(
        child_notification,
        Ok(Notification::OutOfOrder(_))
    ));

    // Check if processed drt is in kel.
    let drt_from_db = event_storage.get_event_at_sn(&child_prefix, 1);
    assert!(matches!(drt_from_db, Ok(None)));

    event_processor.process(deserialized_ixn_drt.clone())?;

    // Check if processed event is in db.
    let ixn_from_db = event_storage.get_event_at_sn(&bobs_pref, 2)?.unwrap();
    assert_eq!(
        ixn_from_db.signed_event_message.event_message.serialize()?,
        raw_parsed(deserialized_ixn_drt)?
    );

    // Process delegated rotation event once again.
    event_processor.process(deserialized_drt.clone())?;

    // Check if processed drt event is in db.
    let drt_from_db = event_storage.get_event_at_sn(&child_prefix, 1)?.unwrap();
    assert_eq!(
        drt_from_db.signed_event_message.event_message.serialize()?,
        raw_parsed(deserialized_drt)?
    );

    Ok(())
}

#[test]
fn test_compute_state_at_sn() -> Result<(), Error> {
    use crate::event::sections::seal::EventSeal;
    use tempfile::Builder;

    // Create test db and event processor.
    let root = Builder::new().prefix("test-db").tempdir().unwrap();
    fs::create_dir_all(root.path()).unwrap();
    let db = Arc::new(SledEventDatabase::new(root.path()).unwrap());
    let event_processor = EventProcessor::new(Arc::clone(&db));
    let event_storage = EventStorage::new(Arc::clone(&db));

    let kerl_str = br#"{"v":"KERI10JSON00012b_","t":"icp","d":"EkLoyrMO5Og4tEGE3jbFa2ztBuKBsvSoWd-B3AWavA8s","i":"DvcMUsxdQ8skME1osztYfxT0ASRinIWWY9PXA1HZEBhc","s":"0","kt":"1","k":["DvcMUsxdQ8skME1osztYfxT0ASRinIWWY9PXA1HZEBhc"],"nt":"1","n":["EOYC7yD8JWxYErTdyDMP0mnb3enVKcaHb2qlhm0oiurY"],"bt":"0","b":[],"c":[],"a":[]}-AABAALNELI5umSx1AeALticKkicNXdBIgMH_--M6ZTvX3s-yZVphIYqGHUaoy3tyR4HEPaU5lPIQyShuxif-N4qbSBw{"v":"KERI10JSON000160_","t":"rot","d":"EA9Wn0fVikmvkEcgRawMvNMg_sJixXaYtVN4lYbyDRfw","i":"DvcMUsxdQ8skME1osztYfxT0ASRinIWWY9PXA1HZEBhc","s":"1","p":"EkLoyrMO5Og4tEGE3jbFa2ztBuKBsvSoWd-B3AWavA8s","kt":"1","k":["DUerfH5Qj2ZWaFgF2ChQhOghv1msuvy_P2ECYvhBfwK8"],"nt":"1","n":["EyCbKISRNYTwBH0qJe0TYB6WRTXhuwX967OXtTBBlvGg"],"bt":"0","br":[],"ba":[],"a":[]}-AABAA_w_oPn_RVuITn_sZ8UlU4kIHAvuhHNPKKD79VTcejupV6hrpjK5af1v41l5Mwv9-PwGjE2AtJXOTXvvnNUFcBQ{"v":"KERI10JSON0000cb_","t":"ixn","d":"EAlNAhOj7ykfmJPk7K3H0LZAYsn2oz9C9gllFPZ-9ymA","i":"DvcMUsxdQ8skME1osztYfxT0ASRinIWWY9PXA1HZEBhc","s":"2","p":"EA9Wn0fVikmvkEcgRawMvNMg_sJixXaYtVN4lYbyDRfw","a":[]}-AABAAZ7dC36qpZxrk3udl9srq6-5HqnAIU8BBhHzI0R5qK7uE8SH_6fwTNi-ovv4fLlVGPOaXT2EDRLXYcZ6aWhriAQ{"v":"KERI10JSON000160_","t":"rot","d":"ELuakEDF_SP8heFB-TpGpoGPU9oedU-KouMOGDq0PcCo","i":"DvcMUsxdQ8skME1osztYfxT0ASRinIWWY9PXA1HZEBhc","s":"3","p":"EAlNAhOj7ykfmJPk7K3H0LZAYsn2oz9C9gllFPZ-9ymA","kt":"1","k":["DB9gO1ODrHs4AVUdX1iE8D55qGrWYaLVsNbUWEtIQhQA"],"nt":"1","n":["EWyOIQNEBTv-FrkS82g7uI6kIWAU2nSZHDUcnw7_wEHc"],"bt":"0","br":[],"ba":[],"a":[]}-AABAAAAu3pjs210AwLQFDLaM41VZtL9gLsaddziRmKPyDx_pESM8BwP81Rcl0ZMc96IN1CVDODc0a9I1AqSXix2_MCw{"v":"KERI10JSON000160_","t":"rot","d":"EMaJomeq41pa3lNAi16ll4PoyjnO_dJ3Dce8c7KGoXJU","i":"DvcMUsxdQ8skME1osztYfxT0ASRinIWWY9PXA1HZEBhc","s":"4","p":"ELuakEDF_SP8heFB-TpGpoGPU9oedU-KouMOGDq0PcCo","kt":"1","k":["DVPbgLTKwPeDQfwaCwNM0LtTKcJbnPlurjVvpP4G4WYw"],"nt":"1","n":["EjiEf0Atq-NcEEGXLRBU4SZs_mRWvjBfSuGWv6kj1akU"],"bt":"0","br":[],"ba":[],"a":[]}-AABAAcXhQ8FeRY8QIT14Y7_1dIsvoO6na9ZbdhSav_DV80t2k-6zPJbiLjjaBCqdQik-Vk5vK5EDwMZQ1L2mJBUutBA{"v":"KERI10JSON0000ff_","t":"ixn","d":"ECKCfB0GL7AHZxPDHkDHszMBONJkixVkSbd8hXWdjeLU","i":"DvcMUsxdQ8skME1osztYfxT0ASRinIWWY9PXA1HZEBhc","s":"5","p":"EMaJomeq41pa3lNAi16ll4PoyjnO_dJ3Dce8c7KGoXJU","a":[,{"d""E7JCRX6JqsBKomojsyLR-TddsSt_Wq9H8EOMhsPyhjR0"}]}-AABAAO9jAkJAGSTcaY_FYT0p3MFbTdKuZO1IJoJbNZVh2nlhvPRLYEFWStT2XiG_8m_Y7ecA9U92eP6-N7X1cCYG8Ag"#;
    // Process kerl
    signed_event_stream(kerl_str)
        .unwrap()
        .1
        .into_iter()
        .for_each(|event| {
            event_processor
                .process(Message::try_from(event.clone()).unwrap())
                .unwrap();
        });

    let event_seal = EventSeal {
        prefix: "DvcMUsxdQ8skME1osztYfxT0ASRinIWWY9PXA1HZEBhc".parse()?,
        sn: 2,
        event_digest: "EAlNAhOj7ykfmJPk7K3H0LZAYsn2oz9C9gllFPZ-9ymA".parse()?,
    };

    let state_at_sn = event_storage
        .compute_state_at_sn(&event_seal.prefix, event_seal.sn)?
        .unwrap();
    assert_eq!(state_at_sn.sn, event_seal.sn);
    assert_eq!(state_at_sn.prefix, event_seal.prefix);
    assert_eq!(event_seal.event_digest, state_at_sn.last_event_digest);

    Ok(())
}

#[test]
pub fn test_not_fully_witnessed() -> Result<(), Error> {
    use tempfile::Builder;

    // Create test db and event processor.
    // events taken from keripy/tests/core/test_witness.py:def test_indexed_witness_replay():
    let root = Builder::new().prefix("test-db").tempdir().unwrap();
    fs::create_dir_all(root.path()).unwrap();
    let db = Arc::new(SledEventDatabase::new(root.path()).unwrap());
    let event_processor = EventProcessor::new(Arc::clone(&db));
    let event_storage = EventStorage::new(Arc::clone(&db));
    let publisher = default_escrow_bus(db.clone());

    // check if receipt was escrowed
    let id = &"E1EyzzujHLiQbj9kcJ9wI2lVjOkiNbNn7t4Y2MhRjn_U"
        .parse()
        .unwrap();

    // process icp event without processing receipts.
    let icp_raw = br#"{"v":"KERI10JSON000273_","t":"icp","d":"E1EyzzujHLiQbj9kcJ9wI2lVjOkiNbNn7t4Y2MhRjn_U","i":"E1EyzzujHLiQbj9kcJ9wI2lVjOkiNbNn7t4Y2MhRjn_U","s":"0","kt":"2","k":["DtD9PUcL_NlTlvc2xiEJBRfRz0bDJlbtTynOQpNwVKh0","Dxb9OSQWxq59UsjRthaNPtTzNn8VXs8SJEXdbxFUZ-lA","DkQFb_911LXVQaFj-Ch9rj89QTpIZT3AcV-TjcBhbXOw"],"nt":"2","n":["EmigdEgCEjPPykB-u4_oW6xENmrnr1M0dNlkIUsx3dEI","EwnTsM2S1AKDnSjrnQF2OWRoPkcpH7aY1-3TtEJwnBMs","Eywk7noH2HheSFbjI-sids93CyzP4LUyJSOUBe7OAQbo"],"bt":"2","b":["B389hKezugU2LFKiFVbitoHAxXqJh6HQ8Rn9tH7fxd68","Bed2Tpxc8KeCEWoq3_RKKRjU_3P-chSser9J4eAtAK6I","BljDbmdNfb63KOpGV4mmPKwyyp3OzDsRzpNrdL1BRQts"],"c":[],"a":[]}-AADAAhZMZp-TpUuGjfO-_s3gSh_aDpuK38b7aVh54W0LzgrOvA5Q3eULEch0hW8Ct6jHfLXSNCrsNSynT3D2UvymdCQABiDU4uO1sZcKh7_qlkVylf_jZDOAWlcJFY_ImBOIcfEZbNthQefZOL6EDzuxdUMEScKTnO_n1q3Ms8rufcz8lDwACQuxdJRTtPypGECC3nHdVkJeQojfRvkRZU7n15111NFbLAY2GpMAOnvptzIVUiv9ONOSCXBCWNFC4kNQmtDWOBg"#;
    let parsed_icp = signed_message(icp_raw).unwrap().1;
    let icp_msg = Message::try_from(parsed_icp).unwrap();
    let res = event_processor.process(icp_msg.clone());
    assert!(matches!(res, Ok(Notification::PartiallyWitnessed(_))));
    publisher.notify(&res?)?;

    let state = event_storage.get_state(id)?;
    assert_eq!(state, None);

    // check if icp is in escrow
    let mut esc = db.get_all_partially_witnessed().unwrap();
    assert_eq!(
        icp_msg,
        Message::Event(esc.next().unwrap().signed_event_message)
    );
    assert!(esc.next().is_none());

    let receipt0_0 = br#"{"v":"KERI10JSON000091_","t":"rct","d":"E1EyzzujHLiQbj9kcJ9wI2lVjOkiNbNn7t4Y2MhRjn_U","i":"E1EyzzujHLiQbj9kcJ9wI2lVjOkiNbNn7t4Y2MhRjn_U","s":"0"}-CABB389hKezugU2LFKiFVbitoHAxXqJh6HQ8Rn9tH7fxd680BlnRQL6bqNGJZNNGGwA4xZhBwtzY1SgAMdIFky-sUiq6bU-DGbp1OHSXQzKGQWlhohRxfcjtDjql8s9B_n5DdDw"#;
    let parsed_rcp = signed_message(receipt0_0).unwrap().1;
    let rcp_msg = Message::try_from(parsed_rcp).unwrap();
    let notification = event_processor.process(rcp_msg.clone())?;
    assert!(matches!(notification, Notification::ReceiptOutOfOrder(_)));
    publisher.notify(&notification)?;

    // check if icp still in escrow
    let mut esc = db.get_all_partially_witnessed().unwrap();
    assert_eq!(
        icp_msg,
        Message::Event(esc.next().unwrap().signed_event_message)
    );
    assert!(esc.next().is_none());

    let mut esc = db.get_escrow_nt_receipts(id).unwrap();
    assert_eq!(rcp_msg, Message::NontransferableRct(esc.next().unwrap()));
    assert!(esc.next().is_none());

    let state = event_storage.get_state(id)?;
    assert_eq!(state, None);

    let receipt0_1 = br#"{"v":"KERI10JSON000091_","t":"rct","d":"E1EyzzujHLiQbj9kcJ9wI2lVjOkiNbNn7t4Y2MhRjn_U","i":"E1EyzzujHLiQbj9kcJ9wI2lVjOkiNbNn7t4Y2MhRjn_U","s":"0"}-CABBed2Tpxc8KeCEWoq3_RKKRjU_3P-chSser9J4eAtAK6I0BC69-inoBzibkf_HOUfn31sP3FOCukY0VqqOnnm6pxPWeBR2N7AhdN146OsHVuWfrzzuDSuJl3GpIPYCIynuEDA"#;
    let parsed_rcp = signed_message(receipt0_1).unwrap().1;
    let rcp_msg = Message::try_from(parsed_rcp).unwrap();
    let notification = event_processor.process(rcp_msg.clone())?;
    publisher.notify(&notification)?;

    // check if icp still in escrow
    let mut esc = db.get_all_partially_witnessed().unwrap();
    assert!(esc.next().is_none());

    // check if receipt was escrowed
    let mut esc = db.get_escrow_nt_receipts(id).unwrap();
    assert!(esc.next().is_none());

    // check if receipt was escrowed
    let esc = db.get_receipts_nt(id).unwrap();
    assert_eq!(esc.count(), 2);

    let state = event_storage.get_state(id)?.unwrap();
    assert_eq!(state.sn, 0);

    let receipt0_2 = br#"{"v":"KERI10JSON000091_","t":"rct","d":"E1EyzzujHLiQbj9kcJ9wI2lVjOkiNbNn7t4Y2MhRjn_U","i":"E1EyzzujHLiQbj9kcJ9wI2lVjOkiNbNn7t4Y2MhRjn_U","s":"0"}-CABBljDbmdNfb63KOpGV4mmPKwyyp3OzDsRzpNrdL1BRQts0BoXmoK-pNlcmdAzgWadjnhhfr2eAKiNxCqoWvx05tQyeZZazJx9rW-wQ_jjLieC7OsKDs6c0rEDHFaVgI9SfkDg"#;
    let parsed_rcp = signed_message(receipt0_2).unwrap().1;
    let rcp_msg = Message::try_from(parsed_rcp).unwrap();
    let notification = event_processor.process(rcp_msg.clone())?;
    publisher.notify(&notification)?;

    // check if receipt was escrowed
    let mut esc = db.get_escrow_nt_receipts(id).unwrap();
    assert!(esc.next().is_none());

    let esc = db.get_receipts_nt(id).unwrap();
    assert_eq!(esc.count(), 3);

    Ok(())
}

#[cfg(feature = "query")]
#[test]
pub fn test_reply_escrow() -> Result<(), Error> {
    use crate::processor::{escrow::ReplyEscrow, notification::NotificationBus, JustNotification};
    use tempfile::Builder;

    // Create test db and event processor.
    let root = Builder::new().prefix("test-db").tempdir().unwrap();
    fs::create_dir_all(root.path()).unwrap();
    let db = Arc::new(SledEventDatabase::new(root.path()).unwrap());
    let mut publisher = NotificationBus::new();
    publisher.register_observer(
        Arc::new(ReplyEscrow::new(db.clone())),
        vec![
            JustNotification::ReplyOutOfOrder,
            JustNotification::KeyEventAdded,
        ],
    );
    let event_processor = EventProcessor::new(Arc::clone(&db));

    let identifier: IdentifierPrefix = "Et78eYkh8A3H9w6Q87EC5OcijiVEJT8KyNtEGdpPVWV8".parse()?;
    let kel = r#"{"v":"KERI10JSON000120_","t":"icp","d":"Et78eYkh8A3H9w6Q87EC5OcijiVEJT8KyNtEGdpPVWV8","i":"Et78eYkh8A3H9w6Q87EC5OcijiVEJT8KyNtEGdpPVWV8","s":"0","kt":"1","k":["DqI2cOZ06RwGNwCovYUWExmdKU983IasmUKMmZflvWdQ"],"n":"E7FuL3Z_KBgt_QAwuZi1lUFNC69wvyHSxnMFUsKjZHss","bt":"0","b":[],"c":[],"a":[]}-AABAAJEloPu7b4z8v1455StEJ1b7dMIz-P0tKJ_GBBCxQA8JEg0gm8qbS4TWGiHikLoZ2GtLA58l9dzIa2x_otJhoDA{"v":"KERI10JSON000155_","t":"rot","d":"EoU_JzojCvenHLPza5-K7z59yU7efQVrzciNdXoVDmlk","i":"Et78eYkh8A3H9w6Q87EC5OcijiVEJT8KyNtEGdpPVWV8","s":"1","p":"Et78eYkh8A3H9w6Q87EC5OcijiVEJT8KyNtEGdpPVWV8","kt":"1","k":["Dyb48eeVVXD7JAarHFAUffKcgYGvCQ4KWX00myzNLgzU"],"n":"ElBleBp2wS0n927E6W63imv-lRzU10uLYTRKzHNn19IQ","bt":"0","br":[],"ba":[],"a":[]}-AABAAXcEQQlT3id8LpTRDkFKVzF7n0d0w-3n__xgdf7rxTpAWUVsHthZcPtovCVr1kca1MD9QbfFAMpEtUZ02LTi3AQ{"v":"KERI10JSON000155_","t":"rot","d":"EYhzp9WCvSNFT2dVryQpVFiTzuWGbFNhVHNKCqAqBI8A","i":"Et78eYkh8A3H9w6Q87EC5OcijiVEJT8KyNtEGdpPVWV8","s":"2","p":"EoU_JzojCvenHLPza5-K7z59yU7efQVrzciNdXoVDmlk","kt":"1","k":["DyN13SKiF1FsVoVR5C4r_15JJLUBxBXBmkleD5AYWplc"],"n":"Em4tcl6gRcT2OLjbON4iz-fsw0iWQGBtwWic0dJY4Gzo","bt":"0","br":[],"ba":[],"a":[]}-AABAAZgqx0nZk4y2NyxPGypIloZikDzaZMw8EwjisexXwn-nr08jdILP6wvMOKZcxmCbAHJ4kHL_SIugdB-_tEvhBDg{"v":"KERI10JSON000155_","t":"rot","d":"EsL4LnyvTGBqdYC_Ute3ag4XYbu8PdCj70un885pMYpA","i":"Et78eYkh8A3H9w6Q87EC5OcijiVEJT8KyNtEGdpPVWV8","s":"3","p":"EYhzp9WCvSNFT2dVryQpVFiTzuWGbFNhVHNKCqAqBI8A","kt":"1","k":["DrcAz_gmDTuWIHn_mOQDeSK_aJIRiw5IMzPD7igzEDb0"],"n":"E_Y2NMHE0nqrTQLe57VPcM0razmxdxRVbljRCSetdjjI","bt":"0","br":[],"ba":[],"a":[]}-AABAAkk_Z4jS76LBiKrTs8tL32DNMndq5UQJ-NoteiTyOuMZfyP8jgxJQU7AiR7zWQZxzmiF0mT1JureItwDkPli5DA"#;
    let parsed = signed_event_stream(kel.as_bytes()).unwrap().1;
    let kel_events = parsed.into_iter().map(|ev| Message::try_from(ev).unwrap());

    let rest_of_kel = r#"{"v":"KERI10JSON000155_","t":"rot","d":"EChhtlv3ZbdRHk6UKxP2l6Uj1kPmloV4hSjvn7480Sks","i":"Et78eYkh8A3H9w6Q87EC5OcijiVEJT8KyNtEGdpPVWV8","s":"4","p":"EsL4LnyvTGBqdYC_Ute3ag4XYbu8PdCj70un885pMYpA","kt":"1","k":["DcJ_93nB6lFRiuTCKLsP0P-LH2bxgnW7pzsp_i8KEHb4"],"n":"Ej3cpXIF_K6ZFnuoRn2sDz26O1YQzTqYhCpac4Lk7oo4","bt":"0","br":[],"ba":[],"a":[]}-AABAAEk-XVyuGkGtfC6MFUiSsk4o4eWGw-cBKhmZOV3DOy8b2tUB-4t6jY15vo26mn8tauvADPs321xkjX9rNBkhlCw{"v":"KERI10JSON000155_","t":"rot","d":"EfARz_ZQsxvwinu5iJ5ry0OQW8z-kSw0ULYi-EXidRpk","i":"Et78eYkh8A3H9w6Q87EC5OcijiVEJT8KyNtEGdpPVWV8","s":"5","p":"EChhtlv3ZbdRHk6UKxP2l6Uj1kPmloV4hSjvn7480Sks","kt":"1","k":["Dw4Woc1Nto6vNe_oezp3Tw13-YujvCIf7zzy8Ua0VaZU"],"n":"EoKxnsSwdrZK9BSDKV0Am-inFCVwc0dQoco8ykRBNcbE","bt":"0","br":[],"ba":[],"a":[]}-AABAA-6rxkCizrb1fbMWzHAMbiyYqnPUBg_d6lN9Gzla49SZ9eHgxOjRxCE34N0FDObX9UuBGNLO7pIh59OMMtwKdDQ{"v":"KERI10JSON000155_","t":"rot","d":"EJyIhOR7NJjQuV_N6WsQ_qqZc5f09vVwqVnIbuiWxuFs","i":"Et78eYkh8A3H9w6Q87EC5OcijiVEJT8KyNtEGdpPVWV8","s":"6","p":"EfARz_ZQsxvwinu5iJ5ry0OQW8z-kSw0ULYi-EXidRpk","kt":"1","k":["DjGxCjRAVaFiVffhQcPDf04bicivm2TL1LknCL3ujv50"],"n":"EE2EIFJ_RB8iHHWGdFVwxWUYOVryS9_0i-boEELGvg5U","bt":"0","br":[],"ba":[],"a":[]}-AABAAXVtZlgCbE7u5KwWe7Hmlv3NCCkVmccQUemIKand3AcYkoxQvS0KPn5WmlQjdLk6RyVCaK2enGqqeFMSOc01_Cg{"v":"KERI10JSON000155_","t":"rot","d":"EXWLIEK40fQjeYCri1Iy8sQxZzWnJdj1pHPkDBMaodoE","i":"Et78eYkh8A3H9w6Q87EC5OcijiVEJT8KyNtEGdpPVWV8","s":"7","p":"EJyIhOR7NJjQuV_N6WsQ_qqZc5f09vVwqVnIbuiWxuFs","kt":"1","k":["DwTncFFLkqdfOx9ipPwjYMJ-Xqcw6uVgE38WbfAiH0zQ"],"n":"EZt3rYIvWZ3WuVankOuW34wSifHNx9tUjdaUImARVCyU","bt":"0","br":[],"ba":[],"a":[]}-AABAA8penO_Nr-KVvQyhDXK8KAWQfh1qoeDGNwCJ7fLmrYQ0Yx84Uh_vHX0kj41AYelgK0aNrHbaewBVqsASQsSBBDA{"v":"KERI10JSON000155_","t":"rot","d":"EArexnxpGFZv4BnXzj59FrFTxCUEU1Aq3Co2iP7tA5aA","i":"Et78eYkh8A3H9w6Q87EC5OcijiVEJT8KyNtEGdpPVWV8","s":"8","p":"EXWLIEK40fQjeYCri1Iy8sQxZzWnJdj1pHPkDBMaodoE","kt":"1","k":["DOedRyfIQe4Z-GNSlbgA8txIKyx4Li2tJ1S0Yhy7l2T8"],"n":"EuiVoq5iFTwRutHDNJHbIY43bBj3EKmk7_lmZJdPj-PU","bt":"0","br":[],"ba":[],"a":[]}-AABAAkZNVe95o9nSNSP6ck_khDy1tfKJUzu430vAi_p6fEMqVzJB4yqa2fdRBJmqwbq5gPOHwd0bE_JcbTrgnVFAQBQ"#;
    let parsed = signed_event_stream(rest_of_kel.as_bytes()).unwrap().1;
    let rest_of_kel = parsed.into_iter().map(|ev| Message::try_from(ev).unwrap());

    let old_rpy = r#"{"v":"KERI10JSON000292_","t":"rpy","d":"E_v_Syz2Bhh1WCKx9GBSpU4g9FqqxtSNPI_M2KgMC1yI","dt":"2021-01-01T00:00:00.000000+00:00","r":"/ksn/Et78eYkh8A3H9w6Q87EC5OcijiVEJT8KyNtEGdpPVWV8","a":{"v":"KERI10JSON0001d7_","i":"Et78eYkh8A3H9w6Q87EC5OcijiVEJT8KyNtEGdpPVWV8","s":"3","p":"EYhzp9WCvSNFT2dVryQpVFiTzuWGbFNhVHNKCqAqBI8A","d":"EsL4LnyvTGBqdYC_Ute3ag4XYbu8PdCj70un885pMYpA","f":"3","dt":"2021-01-01T00:00:00.000000+00:00","et":"rot","kt":"1","k":["DrcAz_gmDTuWIHn_mOQDeSK_aJIRiw5IMzPD7igzEDb0"],"n":"E_Y2NMHE0nqrTQLe57VPcM0razmxdxRVbljRCSetdjjI","bt":"0","b":[],"c":[],"ee":{"s":"3","d":"EsL4LnyvTGBqdYC_Ute3ag4XYbu8PdCj70un885pMYpA","br":[],"ba":[]}}}-FABEt78eYkh8A3H9w6Q87EC5OcijiVEJT8KyNtEGdpPVWV80AAAAAAAAAAAAAAAAAAAAAAwEsL4LnyvTGBqdYC_Ute3ag4XYbu8PdCj70un885pMYpA-AABAAycUrU33S2856nVTuKNbxmGzDwkR9XYY5cXGnpyz4NZsrvt8AdOxfQfYcRCr_URFU9UrEsLFIFJEPoiUEuTbcCg"#;
    let parsed = signed_message(old_rpy.as_bytes()).unwrap().1;
    let deserialized_old_rpy = Message::try_from(parsed).unwrap();

    let new_rpy = r#"{"v":"KERI10JSON000292_","t":"rpy","d":"ECMNs09Snruv7bRpgUGgwflF3ZIpby7_m3jgjdIXJRno","dt":"2021-01-01T00:00:00.000000+00:00","r":"/ksn/Et78eYkh8A3H9w6Q87EC5OcijiVEJT8KyNtEGdpPVWV8","a":{"v":"KERI10JSON0001d7_","i":"Et78eYkh8A3H9w6Q87EC5OcijiVEJT8KyNtEGdpPVWV8","s":"8","p":"EXWLIEK40fQjeYCri1Iy8sQxZzWnJdj1pHPkDBMaodoE","d":"EArexnxpGFZv4BnXzj59FrFTxCUEU1Aq3Co2iP7tA5aA","f":"8","dt":"2021-01-01T00:00:00.000000+00:00","et":"rot","kt":"1","k":["DOedRyfIQe4Z-GNSlbgA8txIKyx4Li2tJ1S0Yhy7l2T8"],"n":"EuiVoq5iFTwRutHDNJHbIY43bBj3EKmk7_lmZJdPj-PU","bt":"0","b":[],"c":[],"ee":{"s":"8","d":"EArexnxpGFZv4BnXzj59FrFTxCUEU1Aq3Co2iP7tA5aA","br":[],"ba":[]}}}-VA0-FABEt78eYkh8A3H9w6Q87EC5OcijiVEJT8KyNtEGdpPVWV80AAAAAAAAAAAAAAAAAAAAACAEArexnxpGFZv4BnXzj59FrFTxCUEU1Aq3Co2iP7tA5aA-AABAA0o_SfwLPA1gA7pZxogj56Dx-n5xELQb0_Nghp7TTQh9-CIOfGQKGHk1FGQm-qRsLPQUEVya7SGKTH0QQjd6uCg"#;
    let parsed = signed_message(new_rpy.as_bytes()).unwrap().1;
    let deserialized_new_rpy = Message::try_from(parsed).unwrap();

    // Try to process out of order reply
    let notification = event_processor.process(deserialized_old_rpy.clone());
    assert!(matches!(notification, Ok(Notification::ReplyOutOfOrder(_))));
    publisher.notify(&notification?)?;
    let escrow = db.get_escrowed_replys(&identifier);
    assert_eq!(escrow.unwrap().collect::<Vec<_>>().len(), 1);

    let accepted_rpys = db.get_accepted_replys(&identifier);
    assert!(accepted_rpys.is_none());

    // process kel events and update escrow
    // reply event should be unescrowed and save as accepted
    kel_events.for_each(|ev| {
        let not = event_processor.process(ev).unwrap();
        publisher.notify(&not).unwrap();
    });

    let escrow = db.get_escrowed_replys(&identifier);
    assert_eq!(escrow.unwrap().collect::<Vec<_>>().len(), 0);

    let accepted_rpys = db.get_accepted_replys(&identifier);
    assert_eq!(accepted_rpys.unwrap().collect::<Vec<_>>().len(), 1);

    // Try to process new out of order reply
    // reply event should be escrowed, accepted reply shouldn't change
    let notification = event_processor.process(deserialized_new_rpy.clone());
    assert!(matches!(notification, Ok(Notification::ReplyOutOfOrder(_))));
    publisher.notify(&notification?)?;
    let mut escrow = db.get_escrowed_replys(&identifier).unwrap();
    assert_eq!(
        Message::KeyStateNotice(escrow.next().unwrap()),
        deserialized_new_rpy
    );
    assert!(escrow.next().is_none());

    let mut accepted_rpys = db.get_accepted_replys(&identifier).unwrap();
    assert_eq!(
        Message::KeyStateNotice(accepted_rpys.next().unwrap()),
        deserialized_old_rpy
    );
    assert!(accepted_rpys.next().is_none());

    // process rest of kel and update escrow
    // reply event should be unescrowed and save as accepted
    rest_of_kel.for_each(|ev| {
        let not = event_processor.process(ev).unwrap();
        publisher.notify(&not).unwrap();
    });

    let escrow = db.get_escrowed_replys(&identifier);
    assert_eq!(escrow.unwrap().collect::<Vec<_>>().len(), 0);

    let mut accepted_rpys = db.get_accepted_replys(&identifier).unwrap();
    assert_eq!(
        Message::KeyStateNotice(accepted_rpys.next().unwrap()),
        deserialized_new_rpy
    );
    assert!(accepted_rpys.next().is_none());

    Ok(())
}

#[test]
fn test_out_of_order() -> Result<(), Error> {
    let kel = br#"{"v":"KERI10JSON00012b_","t":"icp","d":"EWzkqMDJfu5F78Xgw-WWhBChv7zNHJu6oa9UuWR3YARQ","i":"DW-CM1BxXJO2fgMGqgvJBbi0UfxGFI0mpxDBVBNxXKoA","s":"0","kt":"1","k":["DW-CM1BxXJO2fgMGqgvJBbi0UfxGFI0mpxDBVBNxXKoA"],"nt":"1","n":["EIGzh8BtHEKJ2b8tCpT6ViPg_BG1C24J6H1-x3kZgujM"],"bt":"0","b":[],"c":[],"a":[]}-AABAANivtUYYh6eDXCV_B-Bn0hoXhUb1QIKj12v4qEvyfP5Ivv9ptqYECIp1Jh8AGWeQ5jsvvF0Qg4oYr9iRXwTOgDA{"v":"KERI10JSON000160_","t":"rot","d":"EhgEE5xyPyDvZaa61YpXv9olrlgTuYfRAd3eSAxs38tE","i":"DW-CM1BxXJO2fgMGqgvJBbi0UfxGFI0mpxDBVBNxXKoA","s":"1","p":"EWzkqMDJfu5F78Xgw-WWhBChv7zNHJu6oa9UuWR3YARQ","kt":"1","k":["Dv3nISHlvrOn7UjG2YIgBsVsDBnbYBtkmntEMhU3h5Y0"],"nt":"1","n":["E8KLV_FkyNHuhQJWvMWPY1iq69quTjQMqS2h0GJOM8so"],"bt":"0","br":[],"ba":[],"a":[]}-AABAAPagtTdU6s0pzR-rzc2kaw3nl7sVdqALpa73iH5jfphOo-yBP-678rd3CjNUMmaf5l82qI_DUeArUz14y_BGVCA{"v":"KERI10JSON0000cb_","t":"ixn","d":"EWCY9lCq1CmlO-bxxz2xHr3ZRWmpxPaPg9MYOsJe84-4","i":"DW-CM1BxXJO2fgMGqgvJBbi0UfxGFI0mpxDBVBNxXKoA","s":"2","p":"EhgEE5xyPyDvZaa61YpXv9olrlgTuYfRAd3eSAxs38tE","a":[]}-AABAAxMLK-Y1TJ4SZNlEZ-wbGHnmzj_xGLeACwYxdxuFXK8jELRKv1sOYxh-cONWzX3MBr8Tw-CUQcXjdX72urYPJAg{"v":"KERI10JSON000160_","t":"rot","d":"Epkwu4R--j3r_FR2JoDRku4bHk8F824FJAs1JtJr0niY","i":"DW-CM1BxXJO2fgMGqgvJBbi0UfxGFI0mpxDBVBNxXKoA","s":"3","p":"EWCY9lCq1CmlO-bxxz2xHr3ZRWmpxPaPg9MYOsJe84-4","kt":"1","k":["DSrbxtHTjT7h2TKzahHmoPLMUwo_EUM-UAZLhamDbwDo"],"nt":"1","n":["EcoDGJfkoo_db4Q6_eysxz3U-pHE_2PlC7haQx4bYvgA"],"bt":"0","br":[],"ba":[],"a":[]}-AABAAaWu4AEHtTJlZmkKCxsWQzYVgDBPBK2Q-QltsqzNXMexvQZSZ6nbRLXKOl3L8e03ibGCdjgfE68TSaej35gv4CA{"v":"KERI10JSON000160_","t":"rot","d":"EJRFvIIsjIkxcS82a3z5iDnfIG7pFS_sfE42KHdEMas8","i":"DW-CM1BxXJO2fgMGqgvJBbi0UfxGFI0mpxDBVBNxXKoA","s":"4","p":"Epkwu4R--j3r_FR2JoDRku4bHk8F824FJAs1JtJr0niY","kt":"1","k":["DgFazXLwbkgvWpG1C7CkbFIJ73xYXTYsz5ls7Reay9_Q"],"nt":"1","n":["EAsZ5c_oWSgcUnrSOnJGGK_N-rJOG8ZPy8Nf0XYg9Vxc"],"bt":"0","br":[],"ba":[],"a":[]}-AABAAC4-A5mqR3Qe-aQ7kpz2TYIn95Iq3tEQIPhAJFfLDyEpDEwa62sk9mxTsbr71bKCNCZW0QFIcQlNqENBeCx1GBA{"v":"KERI10JSON0000ff_","t":"ixn","d":"EIxaIr-vj-evDQTV9jYu1zGQXm0x4W4sCgnXij0H_mRM","i":"DW-CM1BxXJO2fgMGqgvJBbi0UfxGFI0mpxDBVBNxXKoA","s":"5","p":"EJRFvIIsjIkxcS82a3z5iDnfIG7pFS_sfE42KHdEMas8","a":[,{"d""E7JCRX6JqsBKomojsyLR-TddsSt_Wq9H8EOMhsPyhjR0"}]}-AABAAVWwMR7338dUwKV1hDxHGVyMO91hDBaRDiI2EoxC3kkOlWWRUD_YWwc3dlxDPD8_nPvEkRL7ravw-Cfn9K_BpBQ"#;
    let mut kell = signed_event_stream(kel)
        .unwrap()
        .1
        .into_iter()
        .map(|e| Message::try_from(e).unwrap());
    let ev1 = kell.next().unwrap();
    let ev2 = kell.next().unwrap();
    let ev3 = kell.next().unwrap();
    let ev4 = kell.next().unwrap();
    let ev5 = kell.next().unwrap();

    use tempfile::Builder;

    let (processor, storage, publisher) = {
        let witness_root = Builder::new().prefix("test-db").tempdir().unwrap();
        let path = witness_root.path();
        let witness_db = Arc::new(SledEventDatabase::new(path).unwrap());
        std::fs::create_dir_all(path).unwrap();
        (
            EventProcessor::new(witness_db.clone()),
            EventStorage::new(witness_db.clone()),
            default_escrow_bus(witness_db.clone()),
        )
    };
    let id: IdentifierPrefix = "DW-CM1BxXJO2fgMGqgvJBbi0UfxGFI0mpxDBVBNxXKoA".parse()?;

    let notification = processor.process(ev1)?;
    publisher.notify(&notification)?;
    assert_eq!(storage.get_state(&id).unwrap().unwrap().sn, 0);

    let notification = processor.process(ev4);
    assert!(matches!(notification, Ok(Notification::OutOfOrder(_))));
    publisher.notify(&notification?)?;

    let notification = processor.process(ev3);
    assert!(matches!(notification, Ok(Notification::OutOfOrder(_))));
    publisher.notify(&notification?)?;

    let notification = processor.process(ev5);
    assert!(matches!(notification, Ok(Notification::OutOfOrder(_))));
    publisher.notify(&notification?)?;

    assert_eq!(storage.get_state(&id).unwrap().unwrap().sn, 0);
    // check out of order table
    assert_eq!(storage.db.get_out_of_order_events(&id).unwrap().count(), 3);

    let notification = processor.process(ev2)?;
    publisher.notify(&notification)?;

    assert_eq!(storage.get_state(&id).unwrap().unwrap().sn, 4);
    // Check if out of order is empty
    assert!(storage
        .db
        .get_out_of_order_events(&id)
        .unwrap()
        .next()
        .is_none());

    Ok(())
}

#[test]
fn test_partially_sign_escrow() -> Result<(), Error> {
    use tempfile::Builder;

    // events from keripy/tests/core/test_escrow.py::test_partial_signed_escrow
    let (processor, storage, publisher) = {
        let witness_root = Builder::new().prefix("test-db").tempdir().unwrap();
        let path = witness_root.path();
        let witness_db = Arc::new(SledEventDatabase::new(path).unwrap());
        std::fs::create_dir_all(path).unwrap();
        let processor = EventProcessor::new(witness_db.clone());

        (
            processor,
            EventStorage::new(witness_db.clone()),
            default_escrow_bus(witness_db.clone()),
        )
    };

    let parse_messagee = |raw_event| {
        let parsed = signed_message(raw_event).unwrap().1;
        Message::try_from(parsed).unwrap()
    };

    let id: IdentifierPrefix = "EOsgPPbBijCbpu3R9N-TMdURgcoFqrjUf3rQiIaJ5L7M".parse()?;
    let icp_raw = br#"{"v":"KERI10JSON000207_","t":"icp","d":"EOsgPPbBijCbpu3R9N-TMdURgcoFqrjUf3rQiIaJ5L7M","i":"EOsgPPbBijCbpu3R9N-TMdURgcoFqrjUf3rQiIaJ5L7M","s":"0","kt":["1/2","1/2","1/2"],"k":["DK4OJI8JOr6oEEUMeSF_X-SbKysfwpKwW-ho5KARvH5c","D1RZLgYke0GmfZm-CH8AsW4HoTU4m-2mFgu8kbwp8jQU","DBVwzum-jPfuUXUcHEWdplB4YcoL3BWGXK0TMoF_NeFU"],"nt":["1/2","1/2","1/2"],"n":["E9tzF91cgL0Xu4UkCqlCbDxXK-HnxmmTIwTi_ySgjGLc","Ez53UFJ6euROznsDhnPr4auhJGgzeM5ln5i-Tlp8V3L4","EPF1apCK5AUL7k4AlFG4pSEgQX0h-kosQ_tfUtPJ_Ti0"],"bt":"0","b":[],"c":[],"a":[]}-AABAAjCyfd63fzueQfpOHGgSl4YvEXsc3IYpdlvXDKfpbicV8pGj2v-TWBDyFqkzIdB7hMhG1iR3IeS7vy3a3catGDg"#;
    let icp_first_sig = parse_messagee(icp_raw);

    let icp_raw = br#"{"v":"KERI10JSON000207_","t":"icp","d":"EOsgPPbBijCbpu3R9N-TMdURgcoFqrjUf3rQiIaJ5L7M","i":"EOsgPPbBijCbpu3R9N-TMdURgcoFqrjUf3rQiIaJ5L7M","s":"0","kt":["1/2","1/2","1/2"],"k":["DK4OJI8JOr6oEEUMeSF_X-SbKysfwpKwW-ho5KARvH5c","D1RZLgYke0GmfZm-CH8AsW4HoTU4m-2mFgu8kbwp8jQU","DBVwzum-jPfuUXUcHEWdplB4YcoL3BWGXK0TMoF_NeFU"],"nt":["1/2","1/2","1/2"],"n":["E9tzF91cgL0Xu4UkCqlCbDxXK-HnxmmTIwTi_ySgjGLc","Ez53UFJ6euROznsDhnPr4auhJGgzeM5ln5i-Tlp8V3L4","EPF1apCK5AUL7k4AlFG4pSEgQX0h-kosQ_tfUtPJ_Ti0"],"bt":"0","b":[],"c":[],"a":[]}-AABACJz5biC59pvOpb3aUadlNr_BZb-laG1zgX7FtO5Q0M_HPJObtlhVtUghTBythEb8FpoLze8WnEWUayJnpLsYjAA"#;
    let icp_second_sig = parse_messagee(icp_raw);

    let notification = processor.process(icp_first_sig);
    assert!(matches!(notification, Ok(Notification::PartiallySigned(_))));
    publisher.notify(&notification?)?;

    // check if event was accepted into kel
    assert_eq!(storage.get_state(&id).unwrap(), None);

    // check escrow
    assert_eq!(
        storage
            .db
            .get_all_partially_signed_events()
            .unwrap()
            .count(),
        1
    );

    // Proces the same event with another signature
    let notification = processor.process(icp_second_sig);
    assert!(matches!(notification, Ok(Notification::PartiallySigned(_))));
    publisher.notify(&notification?)?;

    // Now event is fully signed, check if escrow is emty
    assert_eq!(
        storage
            .db
            .get_all_partially_signed_events()
            .unwrap()
            .count(),
        0
    );
    // check if event was accepted
    assert!(storage.get_state(&id).unwrap().is_some());

    let ixn = br#"{"v":"KERI10JSON0000cb_","t":"ixn","d":"ErcMMcfO4fdplItWB_42GwyY21u0pJkQEVDvMmrLVgFc","i":"EOsgPPbBijCbpu3R9N-TMdURgcoFqrjUf3rQiIaJ5L7M","s":"1","p":"EOsgPPbBijCbpu3R9N-TMdURgcoFqrjUf3rQiIaJ5L7M","a":[]}-AABABHu-KLKX52wTZCwE4u_MEWrvPQ8kC_XSgzQ7Mqmrhv4imCCTaoiCCH2JbebIvfOHXlmwVwntz9B89qbf7SLT8Bg"#;
    let ixn_first_sig = parse_messagee(ixn);

    let ixn2 = br#"{"v":"KERI10JSON0000cb_","t":"ixn","d":"ErcMMcfO4fdplItWB_42GwyY21u0pJkQEVDvMmrLVgFc","i":"EOsgPPbBijCbpu3R9N-TMdURgcoFqrjUf3rQiIaJ5L7M","s":"1","p":"EOsgPPbBijCbpu3R9N-TMdURgcoFqrjUf3rQiIaJ5L7M","a":[]}-AABAAye1jlp6iz6h5raVAavZEEahPQ7mUVHxegfjgZCjaWA-UcSQi5ic59-PKQ0tlEHlNHaeKIPts0lvONpW71dgOAg"#;
    let ixn_second_sig = parse_messagee(ixn2);

    let notification = processor.process(ixn_first_sig);
    assert!(matches!(notification, Ok(Notification::PartiallySigned(_))));
    publisher.notify(&notification?)?;

    // check if event was accepted into kel
    assert_eq!(storage.get_state(&id).unwrap().unwrap().sn, 0);

    // check escrow
    assert_eq!(
        storage
            .db
            .get_all_partially_signed_events()
            .unwrap()
            .count(),
        1
    );

    // Proces the same event with another signature
    let notification = processor.process(ixn_second_sig);
    assert!(matches!(notification, Ok(Notification::PartiallySigned(_))));
    publisher.notify(&notification?)?;

    // Now event is fully signed, check if escrow is empty
    assert_eq!(
        storage
            .db
            .get_all_partially_signed_events()
            .unwrap()
            .count(),
        0
    );
    // check if event was accepted
    assert_eq!(storage.get_state(&id).unwrap().unwrap().sn, 1);

    let rot = parse_messagee(br#"{"v":"KERI10JSON0002aa_","t":"rot","d":"Ep2O4Nr3NDhQjPe5IfEQmfW1MExEIj1nUN55ZxboaaQI","i":"EOsgPPbBijCbpu3R9N-TMdURgcoFqrjUf3rQiIaJ5L7M","s":"2","p":"ErcMMcfO4fdplItWB_42GwyY21u0pJkQEVDvMmrLVgFc","kt":["1/2","1/2","1/2"],"k":["DeonYM2bKnAwp6VZcuCXdX72kNFw56czlZ_Tc7XHHVGI","DQghKIy-2do9OkweSgazh3Ql1vCOt5bnc5QF8x50tRoU","DNAUn-5dxm6b8Njo01O0jlStMRCjo9FYQA2mfqFW1_JA"],"nt":[["1/2","1/2","1/2"],["1/1","1/1"]],"n":["ERDESHlo0cEajbxFhWuS8fTBIkYdSlKs3qXm7hNKZV94","E6O7UqeJdpNR99CAFGLMRxvzVWRjrITDW2pLvSQpH_do","EcsXdhvTdA_Si7zimi9ihxlos3Fg_YDKb9J-Qj8XeH50","E8voIy-QfZ3N20SdeOobrTgBgFrmd6BDg3vGuMkkCyGc","EImFU5Xrt6Cv7n8wug9xkJL8_5WwhaI5sXfLZT9Ql9_o"],"bt":"0","br":[],"ba":[],"a":[]}-AADAA1nZhgIcktY781gpGGAb757ylwmaAYi6zsQkEk5Y9wNU-zaEWSXY4ycG3w_Wxt8Xr2zzicMSh6maehmKFx8sMDgABRKx6GPksk0FbaP7w_t6rtoOK-JsBqq6D_-p9t9t79VxEHy8fGCbRUJVxb3TjBckgnqwyjmLVd3RIK3idOYC6DgACszQvR87NLPEcujHLnFgBOGgudSEVXWdnuHfxCBLvSCm3JrELZkpOa5bzAy84PSGeu9MFj0HeuEYj0y4MF9PYCw"#);

    let notification = processor.process(rot)?;
    publisher.notify(&notification)?;
    assert_eq!(storage.get_state(&id).unwrap().unwrap().sn, 2);
    Ok(())
}
