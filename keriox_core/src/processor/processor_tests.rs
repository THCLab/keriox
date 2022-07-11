use std::{convert::TryFrom, fs, sync::Arc};

use crate::{
    derivation::{basic::Basic, self_signing::SelfSigning},
    error::Error,
    event::sections::threshold::SignatureThreshold,
    event_message::{
        event_msg_builder::EventMsgBuilder,
        signed_event_message::{Message, Notice},
        Digestible, EventTypeTag,
    },
    event_parsing::message::{signed_event_stream, signed_message},
    prefix::{AttachedSignaturePrefix, IdentifierPrefix, Prefix, SeedPrefix},
    processor::{
        basic_processor::BasicProcessor, escrow::default_escrow_bus, event_storage::EventStorage,
        Processor,
    },
    signer::Signer, database::{SledEventDatabase, escrow::EscrowDb},
};

#[test]
fn test_process() -> Result<(), Error> {
    use tempfile::Builder;

    // Create test db and event processor.
    let root = Builder::new().prefix("test-db").tempdir().unwrap();
    let escrow_root = Builder::new().prefix("test-db-escrow").tempdir().unwrap();
    fs::create_dir_all(root.path()).unwrap();

    let db = Arc::new(SledEventDatabase::new(root.path()).unwrap());
    let escrow_db = Arc::new(EscrowDb::new(escrow_root.path()).unwrap());
    let (not_bus, (ooo_escrow, ps_escrow)) = default_escrow_bus(db.clone(), escrow_db);
    let event_processor = BasicProcessor::new(Arc::clone(&db), Some(not_bus));
    let event_storage = EventStorage::new(Arc::clone(&db));
    // Events and sigs are from keripy `test_multisig_digprefix` test.
    // (keripy/tests/core/test_eventing.py#1138)

    let icp_raw = br#"{"v":"KERI10JSON0001e7_","t":"icp","d":"EZrJQSdhdiyXNpEzHo-dR0EEbLfcIopBSImdLnQGOKkg","i":"EZrJQSdhdiyXNpEzHo-dR0EEbLfcIopBSImdLnQGOKkg","s":"0","kt":"2","k":["DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA","DVcuJOOJF1IE8svqEtrSuyQjGTd2HhfAkt9y2QkUtFJI","DT1iAhBWCkvChxNWsby2J0pJyxBIxbAtbLA0Ljx-Grh8"],"nt":"2","n":["E_IkdcjsIFrFba-LS1sJDjpec_4vM3XtIPa6D51GcUIw","EU28GjHFKeXzncPxgwlHQZ0iO7f09Y89vy-3VkZ23bBI","E2PRzip7UZ5UTA_1ucb5eoAzxeRS3sIThrSbZhdRaZY8"],"bt":"0","b":[],"c":[],"a":[]}-AADAAzclB26m4VWp5R8ANlTU2qhqE6GA9siAK_vhtqtNNR6qhVed-xEoXRadnL5Jc0kxPZi8XUqSk5KSaOnke_SxXDAABX--x4JGI0Dp0Ran-t1LMg3NEgizu1Jb85LTImofYqD6jz9w5TTPNAmj7rfIFvd4mfJ_ioH0Z0mzLWuIvTIFCBAACQTiHacY3flY9y_Wup66bNzcyQvJUT-WGkv4CPgqkMwq5mOEFf2ps74bur1AE9OSGgrEBlcOQ9HWuTcr80FMKCg"#;
    let parsed = signed_message(icp_raw).unwrap().1;
    let deserialized_icp = Message::try_from(parsed).unwrap();

    let id = match &deserialized_icp {
        Message::Notice(Notice::Event(e)) => e.event_message.event.get_prefix(),
        _ => Err(Error::SemanticError("bad deser".into()))?,
    };

    // Process icp event.
    event_processor.process(&deserialized_icp)?;

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
    event_processor.process(&deserialized_rot.clone())?;
    let rot_from_db = event_storage.get_event_at_sn(&id, 1).unwrap().unwrap();
    assert_eq!(
        rot_from_db.signed_event_message.serialize().unwrap(),
        rot_raw
    );

    // Process the same rotation event one more time.
    event_processor.process(&deserialized_rot)?;
    // should be saved as duplicious event
    assert_eq!(
        event_storage.db.get_duplicious_events(&id).unwrap().count(),
        1
    );

    let ixn_raw = br#"{"v":"KERI10JSON0000cb_","t":"ixn","d":"EA7xKzFFmrQAsu9nOQdePCotb4JLJ7kjHa4k0jQpKjIc","i":"EZrJQSdhdiyXNpEzHo-dR0EEbLfcIopBSImdLnQGOKkg","s":"2","p":"EcR5L1yzQeSOFBdFwmWouiEMzCFC6GhJ28Q2RWta4GxQ","a":[]}-AADAAqLhb_9rU6SYXUm55ZtQOtsY74YfgnLI5xQe8X8hKHgGd1LtLzfFezC9DaFLdz7vpUWWsGEXTs8MqCqfwLVM3BQABrP60M2UVdiZ3T741teIWhjivDxyKUWH9OfX1Sn85O_6Q3qKiipjByGlEZF6WM-FqftKmmtEKH7Uk_bmO2ed-BwAClhKT2EzzOy0oeVNdte3M6knIkaq49Ug-fpin18ey89rDWrg4KApCCpt9mbX2_Hvw5Fy_IuGECmdEVyLJ-XA7Bg"#;
    let parsed = signed_message(ixn_raw).unwrap().1;
    let deserialized_ixn = Message::try_from(parsed).unwrap();

    // Process interaction event.
    event_processor.process(&deserialized_ixn)?;

    // Check if processed event is in db.
    let ixn_from_db = event_storage.get_event_at_sn(&id, 2).unwrap().unwrap();
    match deserialized_ixn {
        Message::Notice(Notice::Event(evt)) => assert_eq!(
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
        Message::Notice(Notice::Event(mut e)) => {
            let sigs = e.signatures[1].clone();
            e.signatures = vec![sigs];
            Notice::Event(e)
        }
        _ => Err(Error::SemanticError("bad deser".into()))?,
    };

    // Process partially signed interaction event.
    event_processor.process_notice(&partially_signed_deserialized_ixn)?;
    if let Notice::Event(ev) = partially_signed_deserialized_ixn {
        // should be saved in partially signed escrow
        assert_eq!(
            ps_escrow
                .get_partially_signed_for_event(ev.event_message)
                .unwrap()
                .count(),
            1
        );
    };

    // Check if processed ixn event is in kel. It shouldn't because of not enough signatures.
    let ixn_from_db = event_storage.get_event_at_sn(&id, 3);
    assert!(matches!(ixn_from_db, Ok(None)));

    // Out of order event.
    let out_of_order_rot_raw = br#"{"v":"KERI10JSON000190_","t":"rot","d":"EZPbvFYRgYz5QBGTgV05eJhngeUGUnFQs8sRWyD8hao0","i":"EZrJQSdhdiyXNpEzHo-dR0EEbLfcIopBSImdLnQGOKkg","s":"4","p":"E8Megu9lmfm1o94jBXuhZHL_khCVrn5Bc5_kmc_dNck4","kt":"2","k":["D4JDgo3WNSUpt-NG14Ni31_GCmrU0r38yo7kgDuyGkQM","DVjWcaNX2gCkHOjk6rkmqPBCxkRCqwIJ-3OjdYmMwxf4","DT1nEDepd6CSAMCE7NY_jlLdG6_mKUlKS_mW-2HJY1hg"],"nt":"0","n":[],"bt":"0","br":[],"ba":[],"a":[]}-AADAAVnoy6-LOPD5YN6yNFrQ1qekdi5RfihxDfZvBfoXunke8bVG9WKG6WVVoWLQRvPNq2LbOohPXN8mHaFue_i2fAgAB31vF_2rZnUUhzphg7dhD6PmuAexG9sgTfSv0Jf_y8DKxD3gMkDDnG78ramDa06kIjil5NcoulHKqUhybQRkkDwACDvEQck1y_W-0MMM04bIeXBvmbbYmH1Yd97psuRCLmFk2vHE0hGJ0v0o4HtRZY5Bm8L2Oqr3YCEOr-Li1ls1vCA"#;
    let parsed = signed_message(out_of_order_rot_raw).unwrap().1;
    let out_of_order_rot = Message::try_from(parsed).unwrap();

    event_processor.process(&out_of_order_rot)?;
    // should be saved in out of order escrow
    assert_eq!(
        ooo_escrow.escrowed_out_of_order.get(&id).unwrap().count(),
        1
    );

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
fn test_process_delegated() -> Result<(), Error> {
    use tempfile::Builder;
    // Create test db and event processor.
    let root = Builder::new().prefix("test-db").tempdir().unwrap();
    fs::create_dir_all(root.path()).unwrap();
    let db = Arc::new(SledEventDatabase::new(root.path()).unwrap());

    let escrow_root = Builder::new().prefix("test-db-escrow").tempdir().unwrap();
    fs::create_dir_all(root.path()).unwrap();
    let escrow_db = Arc::new(EscrowDb::new(escrow_root.path()).unwrap());

    let (not_bus, _ooo_escrow) = default_escrow_bus(db.clone(), escrow_db);

    let event_processor = BasicProcessor::new(Arc::clone(&db), Some(not_bus));
    let event_storage = EventStorage::new(Arc::clone(&db));

    // Events and sigs are from keripy `test_delegation` test.
    // (keripy/tests/core/test_delegating.py)

    let delegator_icp = br#"{"v":"KERI10JSON00012b_","t":"icp","d":"E7YbTIkWWyNwOxZQTTnrs6qn8jFbu2A8zftQ33JYQFQ0","i":"E7YbTIkWWyNwOxZQTTnrs6qn8jFbu2A8zftQ33JYQFQ0","s":"0","kt":"1","k":["DqI2cOZ06RwGNwCovYUWExmdKU983IasmUKMmZflvWdQ"],"nt":"1","n":["EOmBSdblll8qB4324PEmETrFN-DhElyZ0BcBH1q1qukw"],"bt":"0","b":[],"c":[],"a":[]}-AABAAotHSmS5LuCg2LXwlandbAs3MFR0yTC5BbE2iSW_35U2qA0hP9gp66G--mHhiFmfHEIbBKrs3tjcc8ySvYcpiBg"#;
    let parsed = signed_message(delegator_icp).unwrap().1;
    let msg = Message::try_from(parsed).unwrap();
    event_processor.process(&msg)?;
    let delegator_prefix = "E7YbTIkWWyNwOxZQTTnrs6qn8jFbu2A8zftQ33JYQFQ0".parse()?;

    // Delegated inception event.
    let dip_raw = br#"{"v":"KERI10JSON00015f_","t":"dip","d":"ESVGDRnpHMCAESkvj2bxKGAmMloX6K6vxfcmBLTOCM0A","i":"ESVGDRnpHMCAESkvj2bxKGAmMloX6K6vxfcmBLTOCM0A","s":"0","kt":"1","k":["DuK1x8ydpucu3480Jpd1XBfjnCwb3dZ3x5b1CJmuUphA"],"nt":"1","n":["Ej1L6zmDszZ8GmBdYGeUYmAwoT90h3Dt9kRAS90nRyqI"],"bt":"0","b":[],"c":[],"a":[],"di":"E7YbTIkWWyNwOxZQTTnrs6qn8jFbu2A8zftQ33JYQFQ0"}-AABAAbb1dks4dZCRcibL74840WKKtk9wsdMLLlmNFkjb1s7hBfevCqpN8nkZaewQFZu5QWR-rbZtN-Y8DDQ8lh_1WDA-GAB0AAAAAAAAAAAAAAAAAAAAAAQE4ncGiiaG9wbKMHrACX9iPxb7fMSSeBSnngBNIRoZ2_A"#;
    let parsed = signed_message(dip_raw).unwrap().1;
    let deserialized_dip = Message::try_from(parsed).unwrap();

    let child_prefix = "ESVGDRnpHMCAESkvj2bxKGAmMloX6K6vxfcmBLTOCM0A".parse()?;

    // Delegators's ixn event with delegating event seal.
    let delegator_ixn = br#"{"v":"KERI10JSON00013a_","t":"ixn","d":"E4ncGiiaG9wbKMHrACX9iPxb7fMSSeBSnngBNIRoZ2_A","i":"E7YbTIkWWyNwOxZQTTnrs6qn8jFbu2A8zftQ33JYQFQ0","s":"1","p":"E7YbTIkWWyNwOxZQTTnrs6qn8jFbu2A8zftQ33JYQFQ0","a":[{"i":"ESVGDRnpHMCAESkvj2bxKGAmMloX6K6vxfcmBLTOCM0A","s":"0","d":"ESVGDRnpHMCAESkvj2bxKGAmMloX6K6vxfcmBLTOCM0A"}]}-AABAARpc88hIeWV9Z2IvzDl7dRHP-g1-EOYZLiDKyjNZB9PDSeGcNTj_SUXgWIVNdssPL7ajYvglbvxRwIU8teoFHCA"#;
    let parsed = signed_message(delegator_ixn).unwrap().1;
    let deserialized_ixn = Message::try_from(parsed).unwrap();
    event_processor.process(&deserialized_ixn)?;

    // Helper function for serializing message (without attachments)
    let raw_parsed = |ev: Message| -> Result<Vec<_>, Error> {
        if let Message::Notice(Notice::Event(ev)) = ev {
            ev.event_message.serialize()
        } else {
            Ok(vec![])
        }
    };

    // Check if processed event is in db.
    let ixn_from_db = event_storage
        .get_event_at_sn(&delegator_prefix, 1)
        .unwrap()
        .unwrap();
    assert_eq!(
        ixn_from_db.signed_event_message.event_message.serialize()?,
        raw_parsed(deserialized_ixn)?
    );

    // Process delegated inception event.
    event_processor.process(&deserialized_dip)?;

    // Check if processed dip event is in db.
    let dip_from_db = event_storage.get_event_at_sn(&child_prefix, 0)?.unwrap();

    assert_eq!(
        dip_from_db.signed_event_message.event_message.serialize()?,
        raw_parsed(deserialized_dip.clone())?
    );

    // Delegator's interaction event with delegated event seal.
    let delegator_ixn = br#"{"v":"KERI10JSON00013a_","t":"ixn","d":"EAh9mAkWlONIqJPdhMFQ4a9jx4nZWz7JW6wLp9T2YFqk","i":"E7YbTIkWWyNwOxZQTTnrs6qn8jFbu2A8zftQ33JYQFQ0","s":"2","p":"E4ncGiiaG9wbKMHrACX9iPxb7fMSSeBSnngBNIRoZ2_A","a":[{"i":"ESVGDRnpHMCAESkvj2bxKGAmMloX6K6vxfcmBLTOCM0A","s":"1","d":"EnjU4Rc4YtHFV7ezc6FbmXWNdT4QGE2sTtl-yaGXH-ag"}]}-AABAAEGO3wl32as1yxubkrY19x_BwntHVl7jAXHhUpFEPkkpkBxA9lbIG_vhe6-gm-GT6pwKg_pfPDr7pWTZ5sgR5AQ"#;
    let parsed = signed_message(delegator_ixn).unwrap().1;
    let deserialized_ixn_drt = Message::try_from(parsed).unwrap();

    event_processor.process(&deserialized_ixn_drt)?;

    // Check if processed event is in db.
    let ixn_from_db = event_storage
        .get_event_at_sn(&delegator_prefix, 2)?
        .unwrap();
    assert_eq!(
        ixn_from_db.signed_event_message.event_message.serialize()?,
        raw_parsed(deserialized_ixn_drt)?
    );

    // Delegated rotation event.
    let drt_raw = br#"{"v":"KERI10JSON000160_","t":"drt","d":"EnjU4Rc4YtHFV7ezc6FbmXWNdT4QGE2sTtl-yaGXH-ag","i":"ESVGDRnpHMCAESkvj2bxKGAmMloX6K6vxfcmBLTOCM0A","s":"1","p":"ESVGDRnpHMCAESkvj2bxKGAmMloX6K6vxfcmBLTOCM0A","kt":"1","k":["DTf6QZWoet154o9wvzeMuNhLQRr8JaAUeiC6wjB_4_08"],"nt":"1","n":["EJHd79BFLgnljYhhWP2wmc6RD3A12oHDJhkixwNe2sH0"],"bt":"0","br":[],"ba":[],"a":[]}-AABAA9-6k6bExTqgFDG8akEA7ifbMPxsWDe0ttdAXpm3HiYdjfTlY5-vUcDZ1e6RHs6xLADNiNhmKHAuRQW8nmFyPBw-GAB0AAAAAAAAAAAAAAAAAAAAAAgEAh9mAkWlONIqJPdhMFQ4a9jx4nZWz7JW6wLp9T2YFqk"#;
    let parsed = signed_message(drt_raw).unwrap().1;
    let deserialized_drt = Message::try_from(parsed).unwrap();

    // Process drt event.
    event_processor.process(&deserialized_drt)?;

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
    use tempfile::Builder;

    use crate::event::sections::seal::EventSeal;

    // Create test db and event processor.
    let root = Builder::new().prefix("test-db").tempdir().unwrap();
    fs::create_dir_all(root.path()).unwrap();
    let db = Arc::new(SledEventDatabase::new(root.path()).unwrap());

    let escrow_root = Builder::new().prefix("test-db-escrow").tempdir().unwrap();
    fs::create_dir_all(root.path()).unwrap();
    let escrow_db = Arc::new(EscrowDb::new(escrow_root.path()).unwrap());

    let (not_bus, _ooo_escrow) = default_escrow_bus(db.clone(), escrow_db);

    let event_processor = BasicProcessor::new(Arc::clone(&db), Some(not_bus));
    let event_storage = EventStorage::new(Arc::clone(&db));

    let kerl_str = br#"{"v":"KERI10JSON00012b_","t":"icp","d":"EkLoyrMO5Og4tEGE3jbFa2ztBuKBsvSoWd-B3AWavA8s","i":"DvcMUsxdQ8skME1osztYfxT0ASRinIWWY9PXA1HZEBhc","s":"0","kt":"1","k":["DvcMUsxdQ8skME1osztYfxT0ASRinIWWY9PXA1HZEBhc"],"nt":"1","n":["EOYC7yD8JWxYErTdyDMP0mnb3enVKcaHb2qlhm0oiurY"],"bt":"0","b":[],"c":[],"a":[]}-AABAALNELI5umSx1AeALticKkicNXdBIgMH_--M6ZTvX3s-yZVphIYqGHUaoy3tyR4HEPaU5lPIQyShuxif-N4qbSBw{"v":"KERI10JSON000160_","t":"rot","d":"EA9Wn0fVikmvkEcgRawMvNMg_sJixXaYtVN4lYbyDRfw","i":"DvcMUsxdQ8skME1osztYfxT0ASRinIWWY9PXA1HZEBhc","s":"1","p":"EkLoyrMO5Og4tEGE3jbFa2ztBuKBsvSoWd-B3AWavA8s","kt":"1","k":["DUerfH5Qj2ZWaFgF2ChQhOghv1msuvy_P2ECYvhBfwK8"],"nt":"1","n":["EyCbKISRNYTwBH0qJe0TYB6WRTXhuwX967OXtTBBlvGg"],"bt":"0","br":[],"ba":[],"a":[]}-AABAA_w_oPn_RVuITn_sZ8UlU4kIHAvuhHNPKKD79VTcejupV6hrpjK5af1v41l5Mwv9-PwGjE2AtJXOTXvvnNUFcBQ{"v":"KERI10JSON0000cb_","t":"ixn","d":"EAlNAhOj7ykfmJPk7K3H0LZAYsn2oz9C9gllFPZ-9ymA","i":"DvcMUsxdQ8skME1osztYfxT0ASRinIWWY9PXA1HZEBhc","s":"2","p":"EA9Wn0fVikmvkEcgRawMvNMg_sJixXaYtVN4lYbyDRfw","a":[]}-AABAAZ7dC36qpZxrk3udl9srq6-5HqnAIU8BBhHzI0R5qK7uE8SH_6fwTNi-ovv4fLlVGPOaXT2EDRLXYcZ6aWhriAQ{"v":"KERI10JSON000160_","t":"rot","d":"ELuakEDF_SP8heFB-TpGpoGPU9oedU-KouMOGDq0PcCo","i":"DvcMUsxdQ8skME1osztYfxT0ASRinIWWY9PXA1HZEBhc","s":"3","p":"EAlNAhOj7ykfmJPk7K3H0LZAYsn2oz9C9gllFPZ-9ymA","kt":"1","k":["DB9gO1ODrHs4AVUdX1iE8D55qGrWYaLVsNbUWEtIQhQA"],"nt":"1","n":["EWyOIQNEBTv-FrkS82g7uI6kIWAU2nSZHDUcnw7_wEHc"],"bt":"0","br":[],"ba":[],"a":[]}-AABAAAAu3pjs210AwLQFDLaM41VZtL9gLsaddziRmKPyDx_pESM8BwP81Rcl0ZMc96IN1CVDODc0a9I1AqSXix2_MCw{"v":"KERI10JSON000160_","t":"rot","d":"EMaJomeq41pa3lNAi16ll4PoyjnO_dJ3Dce8c7KGoXJU","i":"DvcMUsxdQ8skME1osztYfxT0ASRinIWWY9PXA1HZEBhc","s":"4","p":"ELuakEDF_SP8heFB-TpGpoGPU9oedU-KouMOGDq0PcCo","kt":"1","k":["DVPbgLTKwPeDQfwaCwNM0LtTKcJbnPlurjVvpP4G4WYw"],"nt":"1","n":["EjiEf0Atq-NcEEGXLRBU4SZs_mRWvjBfSuGWv6kj1akU"],"bt":"0","br":[],"ba":[],"a":[]}-AABAAcXhQ8FeRY8QIT14Y7_1dIsvoO6na9ZbdhSav_DV80t2k-6zPJbiLjjaBCqdQik-Vk5vK5EDwMZQ1L2mJBUutBA{"v":"KERI10JSON0000ff_","t":"ixn","d":"ECKCfB0GL7AHZxPDHkDHszMBONJkixVkSbd8hXWdjeLU","i":"DvcMUsxdQ8skME1osztYfxT0ASRinIWWY9PXA1HZEBhc","s":"5","p":"EMaJomeq41pa3lNAi16ll4PoyjnO_dJ3Dce8c7KGoXJU","a":[,{"d""E7JCRX6JqsBKomojsyLR-TddsSt_Wq9H8EOMhsPyhjR0"}]}-AABAAO9jAkJAGSTcaY_FYT0p3MFbTdKuZO1IJoJbNZVh2nlhvPRLYEFWStT2XiG_8m_Y7ecA9U92eP6-N7X1cCYG8Ag"#;
    // Process kerl
    signed_event_stream(kerl_str)
        .unwrap()
        .1
        .into_iter()
        .for_each(|event| {
            event_processor
                .process(&Message::try_from(event.clone()).unwrap())
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

/// Helper function to generate keypairs that can be used for signing in tests.
fn setup_signers() -> Vec<Signer> {
    vec![
        "ArwXoACJgOleVZ2PY7kXn7rA0II0mHYDhc6WrBH8fDAc",
        "A6zz7M08-HQSFq92sJ8KJOT2cZ47x7pXFQLPB0pckB3Q",
        "AcwFTk-wgk3ZT2buPRIbK-zxgPx-TKbaegQvPEivN90Y",
        "Alntkt3u6dDgiQxTATr01dy8M72uuaZEf9eTdM-70Gk8",
        "A1-QxDkso9-MR1A8rZz_Naw6fgaAtayda8hrbkRVVu1E",
        "AKuYMe09COczwf2nIoD5AE119n7GLFOVFlNLxZcKuswc",
        "AxFfJTcSuEE11FINfXMqWttkZGnUZ8KaREhrnyAXTsjw",
        "ALq-w1UKkdrppwZzGTtz4PWYEeWm0-sDHzOv5sq96xJY",
        "AAD8sznuHWMw7cl6eZJQLm8PGBKvCjQzDH1Ui9ygH0Uo",
        "ANqQNn_9UjfayUJNdQobmixrH9qJF1cltKDwDMVkiLg8",
        "A1t7ix1GuZIP48r6ljsoo8jPsB9dEnnWNfhy2XNl1r-c",
        "AhzCysVY12fWXfkH1QkAOCY6oYbVwXOaUjf7YPtIfC8U",
        "A4HrsYq9XfxYK76ffoceNzj9n8tBkXrWNBIXUNdoe5ME",
        "AhpAiPtDqDcEeU_eXlJ8Bk3kJE0g0jdezyXZdBKfXslU",
        "AzN9fKZAZEIn9jMN2fZ2B35MNMQJPAZrNrJQRMi_S_8g",
        "AkNrzLqnqRx9WCpJAwTAOE5oNaDlOgOYiuM9bL4HM9R0",
        "ALjR-EE3jUF2yXW7Tq7WJSh3OFc6-BNxXJ9jGdfwA6Bs",
        "AvpsEhige2ssBrMxskK2xXpeKfed4cvcZCIdRh7fhgiI",
    ]
    .iter()
    .map(|key| {
        let (_pk, sk) = key
            .parse::<SeedPrefix>()
            .unwrap()
            .derive_key_pair()
            .unwrap();
        Signer::new_with_key(&sk.key()).unwrap()
    })
    .collect::<Vec<_>>()
}

#[test]
pub fn test_partial_rotation_simple_threshold() -> Result<(), Error> {
    use tempfile::Builder;
    let db_root = Builder::new().prefix("test-db").tempdir().unwrap();
    let path = db_root.path();
    std::fs::create_dir_all(path).unwrap();
    let db = Arc::new(SledEventDatabase::new(path).unwrap());

    let escrow_root = Builder::new().prefix("test-db-escrow").tempdir().unwrap();
    let escrow_db = Arc::new(EscrowDb::new(escrow_root.path()).unwrap());

    let (not_bus, _ooo_escrow) = default_escrow_bus(db.clone(), escrow_db);

    let processor = BasicProcessor::new(db.clone(), Some(not_bus));
    // setup keypairs
    let signers = setup_signers();

    let keys = vec![Basic::Ed25519.derive(signers[0].public_key())];
    let next_pks = signers[1..6]
        .iter()
        .map(|signer| Basic::Ed25519.derive(signer.public_key()))
        .collect::<Vec<_>>();
    // build inception event
    let icp = EventMsgBuilder::new(EventTypeTag::Icp)
        .with_keys(keys)
        .with_threshold(&SignatureThreshold::Simple(1))
        .with_next_keys(next_pks)
        .with_next_threshold(&SignatureThreshold::Simple(2))
        .build()
        .unwrap();
    // {"v":"KERI10JSON0001e7_","t":"icp","d":"Eozz_fD_4KNiIZAggGCPcCEbV-mDbvLH_UfVMsC83yLo","i":"Eozz_fD_4KNiIZAggGCPcCEbV-mDbvLH_UfVMsC83yLo","s":"0","kt":"1","k":["DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA"],"nt":"2","n":["E67B6WkwQrEfSA2MylxmF28HJc_HxfHRyK1kRXSYeMiI","EL-1w3eYVzNy0-RQV6r2ZORG-Y4gmOF-S7t9aeZMERXU","E_IkdcjsIFrFba-LS1sJDjpec_4vM3XtIPa6D51GcUIw","EU28GjHFKeXzncPxgwlHQZ0iO7f09Y89vy-3VkZ23bBI","E2PRzip7UZ5UTA_1ucb5eoAzxeRS3sIThrSbZhdRaZY8"],"bt":"0","b":[],"c":[],"a":[]}

    let id_prefix = icp.event.get_prefix();
    let icp_digest = icp.event.get_digest();
    assert_eq!(
        id_prefix,
        IdentifierPrefix::SelfAddressing(icp_digest.clone())
    );
    assert_eq!(
        id_prefix.to_str(),
        "Eozz_fD_4KNiIZAggGCPcCEbV-mDbvLH_UfVMsC83yLo"
    );
    // sign inception event
    let signature = signers[0].sign(icp.serialize().unwrap())?;
    let signed_icp = icp.sign(
        vec![AttachedSignaturePrefix::new(
            SelfSigning::Ed25519Sha512,
            signature,
            0,
        )],
        None,
        None,
    );

    processor.process_notice(&Notice::Event(signed_icp))?;

    // create partial rotation event. Subset of keys set in inception event as
    // next keys
    let current_signers = [&signers[2], &signers[4], &signers[5]];
    let current_public_keys = current_signers
        .iter()
        .map(|sig| Basic::Ed25519.derive(sig.public_key()))
        .collect::<Vec<_>>();
    let next_public_keys = signers[6..11]
        .iter()
        .map(|sig| Basic::Ed25519.derive(sig.public_key()))
        .collect::<Vec<_>>();
    // Generate partial rotation event
    let rotation = EventMsgBuilder::new(EventTypeTag::Rot)
        .with_prefix(&id_prefix)
        .with_previous_event(&icp_digest)
        .with_keys(current_public_keys)
        .with_threshold(&SignatureThreshold::Simple(3))
        .with_next_keys(next_public_keys)
        .with_next_threshold(&SignatureThreshold::Simple(4))
        .build()?;

    let rot_digest = rotation.event.get_digest();

    let signatures = current_signers
        .iter()
        .enumerate()
        .map(|(index, sig)| {
            let signature = sig.sign(rotation.serialize().unwrap()).unwrap();
            AttachedSignaturePrefix::new(SelfSigning::Ed25519Sha512, signature, index as u16)
        })
        .collect::<Vec<_>>();

    let signed_rotation = rotation.sign(signatures, None, None);

    processor.process_notice(&Notice::Event(signed_rotation))?;
    let state = EventStorage::new(db.clone()).get_state(&id_prefix)?;
    assert_eq!(state.unwrap().sn, 1);

    let current_signers = [&signers[6], &signers[7], &signers[8]];
    let next_public_keys = signers[11..16]
        .iter()
        .map(|sig| Basic::Ed25519.derive(sig.public_key()))
        .collect::<Vec<_>>();
    let current_public_keys = current_signers
        .iter()
        .map(|sig| Basic::Ed25519.derive(sig.public_key()))
        .collect::<Vec<_>>();

    //  Partial rotation that will fail because it does not have enough sigs for
    //  prior threshold (`nt`). Next threshold in last roatation event was set
    //  to 4.
    let rotation = EventMsgBuilder::new(EventTypeTag::Rot)
        .with_prefix(&id_prefix)
        .with_keys(current_public_keys)
        .with_threshold(&SignatureThreshold::Simple(3))
        .with_next_keys(next_public_keys)
        .with_next_threshold(&SignatureThreshold::Simple(2))
        .with_sn(2)
        .with_previous_event(&rot_digest)
        .build()?;

    let signatures = current_signers
        .iter()
        .enumerate()
        .map(|(index, sig)| {
            let signature = sig.sign(rotation.serialize().unwrap()).unwrap();
            AttachedSignaturePrefix::new(SelfSigning::Ed25519Sha512, signature, index as u16)
        })
        .collect::<Vec<_>>();

    let signed_rotation = rotation.sign(signatures, None, None);
    let result = processor.process_notice(&Notice::Event(signed_rotation));
    assert!(result.is_err());
    let state = EventStorage::new(db.clone()).get_state(&id_prefix)?;
    assert_eq!(state.unwrap().sn, 1);

    Ok(())
}

#[test]
pub fn test_partial_rotation_weighted_threshold() -> Result<(), Error> {
    use tempfile::Builder;
    let (processor, storage) = {
        let db_root = Builder::new().prefix("test-db").tempdir().unwrap();
        let path = db_root.path();
        std::fs::create_dir_all(path).unwrap();
        let db = Arc::new(SledEventDatabase::new(path).unwrap());

        let escrow_root = Builder::new().prefix("test-db-escrow").tempdir().unwrap();
        let escrow_db = Arc::new(EscrowDb::new(escrow_root.path()).unwrap());

        let (not_bus, _ooo_escrow) = default_escrow_bus(db.clone(), escrow_db);
        (
            BasicProcessor::new(db.clone(), Some(not_bus)),
            EventStorage::new(db.clone()),
        )
    };
    // setup keypairs
    let signers = setup_signers();

    let keys = vec![Basic::Ed25519.derive(signers[0].public_key())];
    let next_pks = signers[1..6]
        .iter()
        .map(|signer| Basic::Ed25519.derive(signer.public_key()))
        .collect::<Vec<_>>();
    // build inception event
    let icp = EventMsgBuilder::new(EventTypeTag::Icp)
        .with_keys(keys)
        .with_threshold(&SignatureThreshold::Simple(1))
        .with_next_keys(next_pks)
        .with_next_threshold(&SignatureThreshold::single_weighted(vec![
            (1, 2),
            (1, 2),
            (1, 3),
            (1, 3),
            (1, 3),
        ]))
        .build()
        .unwrap();

    let id_prefix = icp.event.get_prefix();
    let icp_digest = icp.event.get_digest();
    assert_eq!(
        id_prefix,
        IdentifierPrefix::SelfAddressing(icp_digest.clone())
    );
    assert_eq!(
        id_prefix.to_str(),
        "EtxZNMpv5OheTzkisPAILhrPpvqTEI52tLldrlhPSKxA"
    );
    // sign inception event
    let signature = signers[0].sign(icp.serialize().unwrap())?;
    let signed_icp = icp.sign(
        vec![AttachedSignaturePrefix::new(
            SelfSigning::Ed25519Sha512,
            signature,
            0,
        )],
        None,
        None,
    );

    processor.process_notice(&Notice::Event(signed_icp))?;

    // create partial rotation event. Subset of keys set in inception event as
    // next keys
    let current_signers = [&signers[3], &signers[4], &signers[5]];
    let current_public_keys = current_signers
        .iter()
        .map(|sig| Basic::Ed25519.derive(sig.public_key()))
        .collect::<Vec<_>>();
    let next_public_keys = signers[11..16]
        .iter()
        .map(|sig| Basic::Ed25519.derive(sig.public_key()))
        .collect::<Vec<_>>();

    // Generate partial rotation event
    let rotation = EventMsgBuilder::new(EventTypeTag::Rot)
        .with_prefix(&id_prefix)
        .with_previous_event(&icp_digest)
        .with_keys(current_public_keys.clone())
        .with_threshold(&SignatureThreshold::single_weighted(vec![
            (1, 2),
            (1, 2),
            (1, 3),
        ]))
        .with_next_keys(next_public_keys)
        .with_next_threshold(&SignatureThreshold::single_weighted(vec![
            (1, 2),
            (1, 2),
            (1, 3),
            (1, 3),
            (1, 3),
        ]))
        .build()?;

    let rot_digest = rotation.event.get_digest();

    let signatures = current_signers
        .iter()
        .enumerate()
        .map(|(index, sig)| {
            let signature = sig.sign(rotation.serialize().unwrap()).unwrap();
            AttachedSignaturePrefix::new(SelfSigning::Ed25519Sha512, signature, index as u16)
        })
        .collect::<Vec<_>>();

    let signed_rotation = rotation.sign(signatures, None, None);

    processor.process_notice(&Notice::Event(signed_rotation))?;
    let state = storage.get_state(&id_prefix)?.unwrap();
    assert_eq!(state.sn, 1);
    assert_eq!(&state.current.public_keys, &current_public_keys);
    assert_eq!(
        serde_json::to_string(&state.current.threshold).unwrap(),
        "[\"1/2\",\"1/2\",\"1/3\"]"
    );

    let current_signers = [&signers[13], &signers[14]];
    let next_public_keys = vec![];
    let current_public_keys = current_signers
        .iter()
        .map(|sig| Basic::Ed25519.derive(sig.public_key()))
        .collect::<Vec<_>>();

    //  Partial rotation that will fail because it does not have enough sigs for
    //  prior threshold (`nt`).
    let rotation = EventMsgBuilder::new(EventTypeTag::Rot)
        .with_prefix(&id_prefix)
        .with_keys(current_public_keys)
        .with_threshold(&SignatureThreshold::Simple(2))
        .with_next_keys(next_public_keys)
        .with_next_threshold(&SignatureThreshold::Simple(0))
        .with_sn(2)
        .with_previous_event(&rot_digest)
        .build()?;

    let signatures = current_signers
        .iter()
        .enumerate()
        .map(|(index, sig)| {
            let signature = sig.sign(rotation.serialize().unwrap()).unwrap();
            AttachedSignaturePrefix::new(SelfSigning::Ed25519Sha512, signature, index as u16)
        })
        .collect::<Vec<_>>();

    let signed_rotation = rotation.sign(signatures, None, None);
    let result = processor.process_notice(&Notice::Event(signed_rotation));
    assert!(result.is_err());

    // State shouldn't be updated.
    let state = storage.get_state(&id_prefix)?.unwrap();
    assert_eq!(state.sn, 1);

    Ok(())
}
