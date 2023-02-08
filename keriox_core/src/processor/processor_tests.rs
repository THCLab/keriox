use std::{convert::TryFrom, fs, sync::Arc};

use cesrox::{parse, parse_many, primitives::CesrPrimitive};
use sai::sad::SAD;

use crate::{
    database::{escrow::EscrowDb, SledEventDatabase},
    error::Error,
    event::sections::threshold::SignatureThreshold,
    event_message::{
        event_msg_builder::EventMsgBuilder,
        signed_event_message::{Message, Notice},
        EventTypeTag,
    },
    prefix::{AttachedSignaturePrefix, BasicPrefix, IdentifierPrefix, SelfSigningPrefix},
    processor::{
        basic_processor::BasicProcessor,
        escrow::{default_escrow_bus, EscrowConfig},
        event_storage::EventStorage,
        Processor,
    },
    signer::setup_signers,
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
    let (not_bus, (ooo_escrow, ps_escrow, _pw_escrow, _)) =
        default_escrow_bus(db.clone(), escrow_db, EscrowConfig::default());
    let event_processor = BasicProcessor::new(Arc::clone(&db), Some(not_bus));
    let event_storage = EventStorage::new(Arc::clone(&db));
    // Events and sigs are from keripy `test_multisig_digprefix` test.
    // (keripy/tests/core/test_eventing.py#1138)

    let icp_raw = br#"{"v":"KERI10JSON0001e7_","t":"icp","d":"EBfxc4RiVY6saIFmUfEtETs1FcqmktZW88UkbnOg0Qen","i":"EBfxc4RiVY6saIFmUfEtETs1FcqmktZW88UkbnOg0Qen","s":"0","kt":"2","k":["DErocgXD2RGSyvn3MObcx59jeOsEQhv2TqHirVkzrp0Q","DFXLiTjiRdSBPLL6hLa0rskIxk3dh4XwJLfctkJFLRSS","DE9YgIQVgpLwocTVrG8tidKScsQSMWwLWywNC48fhq4f"],"nt":"2","n":["EDJk5EEpC4-tQ7YDwBiKbpaZahh1QCyQOnZRF7p2i8k8","EAXfDjKvUFRj-IEB_o4y-Y_qeJAjYfZtOMD9e7vHNFss","EN8l6yJC2PxribTN0xfri6bLz34Qvj-x3cNwcV3DvT2m"],"bt":"0","b":[],"c":[],"a":[]}-AADAAD4SyJSYlsQG22MGXzRGz2PTMqpkgOyUfq7cS99sC2BCWwdVmEMKiTEeWe5kv-l_d9auxdadQuArLtAGEArW8wEABD0z_vQmFImZXfdR-0lclcpZFfkJJJNXDcUNrf7a-mGsxNLprJo-LROwDkH5m7tVrb-a1jcor2dHD9Jez-r4bQIACBFeU05ywfZycLdR0FxCvAR9BfV9im8tWe1DglezqJLf-vHRQSChY1KafbYNc96hYYpbuN90WzuCRMgV8KgRsEC"#;
    let parsed = parse(icp_raw).unwrap().1;
    let deserialized_icp = Message::try_from(parsed).unwrap();

    let id = match &deserialized_icp {
        Message::Notice(Notice::Event(e)) => e.event_message.data.get_prefix(),
        _ => Err(Error::SemanticError("bad deser".into()))?,
    };

    // Process icp event.
    event_processor.process(&deserialized_icp)?;

    // Check if processed event is in kel.
    let icp_from_db = event_storage.get_event_at_sn(&id, 0).unwrap();
    let re_serialized = icp_from_db.unwrap().signed_event_message.encode().unwrap();
    assert_eq!(icp_raw.to_vec(), re_serialized);

    let rot_raw = br#"{"v":"KERI10JSON00021c_","t":"rot","d":"EHjzZj4i_-RpTN2Yh-NocajFROJ_GkBtlByhRykqiXgz","i":"EBfxc4RiVY6saIFmUfEtETs1FcqmktZW88UkbnOg0Qen","s":"1","p":"EBfxc4RiVY6saIFmUfEtETs1FcqmktZW88UkbnOg0Qen","kt":"2","k":["DCjxOXniUc5EUzDqERlXdptfKPHy6jNo_ZGsS4Vd8fAE","DNZHARO4dCJlluv0qezEMRmErIWWc-lzOzolBOQ15tHV","DOCQ4KN1jUlKbfjRteDYt9fxgpq1NK9_MqO5IA7shpED"],"nt":"2","n":["EN8l6yJC2PxribTN0xfri6bLz34Qvj-x3cNwcV3DvT2m","EATiZAHl0kzKID6faaQP2O7zB3Hj7eH3bE-vgKVAtsyU","EG6e7dJhh78ZqeIZ-eMbe-OB3TwFMPmrSsh9k75XIjLP"],"bt":"0","br":[],"ba":[],"a":[]}-AADAAAqV6xpsAAEB_FJP5UdYO5qiJphz8cqXbTjB9SRy8V0wIim-lgafF4o-b7TW0spZtzx2RXUfZLQQCIKZsw99k8AABBP8nfF3t6bf4z7eNoBgUJR-hdhw7wnlljMZkeY5j2KFRI_s8wqtcOFx1A913xarGJlO6UfrqFWo53e9zcD8egIACB8DKLMZcCGICuk98RCEVuS0GsqVngi1d-7gAX0jid42qUcR3aiYDMp2wJhqJn-iHJVvtB-LK7TRTggBtMDjuwB"#;
    let parsed = parse(rot_raw).unwrap().1;
    let deserialized_rot = Message::try_from(parsed).unwrap();

    // Process rotation event.
    event_processor.process(&deserialized_rot.clone())?;
    let rot_from_db = event_storage.get_event_at_sn(&id, 1).unwrap().unwrap();
    assert_eq!(rot_from_db.signed_event_message.encode().unwrap(), rot_raw);

    // Process the same rotation event one more time.
    event_processor.process(&deserialized_rot)?;
    // should be saved as duplicious event
    assert_eq!(
        event_storage.db.get_duplicious_events(&id).unwrap().count(),
        1
    );

    let ixn_raw = br#"{"v":"KERI10JSON0000cb_","t":"ixn","d":"EL6Dpm72KXayaUHYvVHlhPplg69fBvRt1P3YzuOGVpmz","i":"EBfxc4RiVY6saIFmUfEtETs1FcqmktZW88UkbnOg0Qen","s":"2","p":"EHjzZj4i_-RpTN2Yh-NocajFROJ_GkBtlByhRykqiXgz","a":[]}-AADAABgep0kbpgl91vvcXziJ7tHY1WVTAcUJyYCBNqTcNuK9AfzLHfKHhJeSC67wFRU845qjLSAC-XwWaqWgyAgw_8MABD5wTnqqJcnLWMA7NZ1vLOTzDspInJrly7O4Kt6Jwzue9z2TXkDXi1jr69JeKbzUQ6c2Ka1qPXAst0JzrOiyuAPACAcLHnOz1Owtgq8mcR_-PpAr91zOTK_Zj9r0V-9P47vzGsYwAxcVshclfhCMhu73aZuZbvQhy9Rxcj-qRz96cIL"#;
    let parsed = parse(ixn_raw).unwrap().1;
    let deserialized_ixn = Message::try_from(parsed).unwrap();

    // Process interaction event.
    event_processor.process(&deserialized_ixn)?;

    // Check if processed event is in db.
    let ixn_from_db = event_storage.get_event_at_sn(&id, 2).unwrap().unwrap();
    match deserialized_ixn {
        Message::Notice(Notice::Event(evt)) => assert_eq!(
            ixn_from_db.signed_event_message.event_message.data,
            evt.event_message.data
        ),
        _ => assert!(false),
    }

    // Construct partially signed interaction event.
    let ixn_raw_2 = br#"{"v":"KERI10JSON0000cb_","t":"ixn","d":"ECS66nEGuig1H1gM88HntPIN0fPQomkQPj7CizREZOEx","i":"EBfxc4RiVY6saIFmUfEtETs1FcqmktZW88UkbnOg0Qen","s":"3","p":"EL6Dpm72KXayaUHYvVHlhPplg69fBvRt1P3YzuOGVpmz","a":[]}-AADAABbMyugocrdH5boKnV6Q9pqMezuizKmYERP_XiZKT2J81zWmbEvrf_WXIa169hfTqF1kLuvWnDpndHyH8xhG9gPABDSfoYPlRHBNhaWjU2S9HU7S0wyAKPvggjINT7TDcTgHWbK3c3hd-nJmEwIi87JJqGmVqKUN-b1smY4Yg3hsP0DACArsDiRVYR8V7t-xClqd6A1qj0kwysyNMdwArEKXZ8D4Cu5yXfKh_KBO4bRsuv7t1jxMnwImVcWLxdKHiGbkwgP"#;
    let parsed = parse(ixn_raw_2).unwrap().1;
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
    } else {
        unreachable!()
    };

    // Check if processed ixn event is in kel. It shouldn't because of not enough signatures.
    let ixn_from_db = event_storage.get_event_at_sn(&id, 3);
    assert!(matches!(ixn_from_db, Ok(None)));

    // Out of order event.
    let out_of_order_rot_raw = br#"{"v":"KERI10JSON000190_","t":"rot","d":"EG3e42rBNZJ_ijLq6Ch2eNRUGRANwEHohGmnR2U_lH92","i":"EBfxc4RiVY6saIFmUfEtETs1FcqmktZW88UkbnOg0Qen","s":"4","p":"ECS66nEGuig1H1gM88HntPIN0fPQomkQPj7CizREZOEx","kt":"2","k":["DOCQ4KN1jUlKbfjRteDYt9fxgpq1NK9_MqO5IA7shpED","DFY1nGjV9oApBzo5Oq5JqjwQsZEQqsCCftzo3WJjMMX-","DE9ZxA3qXegkgDAhOzWP45S3Ruv5ilJSkv5lvthyWNYY"],"nt":"0","n":[],"bt":"0","br":[],"ba":[],"a":[]}-AADAAAyif3K8mg9JE0p98CASi-c9vOhbGqOMUd-CfZGUOTPk3_qfvA-IDLDjm2QDmR6yhAGyhC-6HZRTq8ChC6fIp8OABAHpYJJpsNfNQw6V7QzDWjJ9hfQYq3RlV1XcbxWIXHhwI2nRHxlxyGwufRNeFANZdP10MqcR4IX6nDkdp9YN6IHACBh9wl7YbutrnKfKI-8tCaztpCifUFuR5XY6rOVucWgLXYVJwCYmkl95LMUBJPee4v2pImB0Vftmwt5FJ2lPY8O"#;
    let parsed = parse(out_of_order_rot_raw).unwrap().1;
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

    let id: IdentifierPrefix = "EBfxc4RiVY6saIFmUfEtETs1FcqmktZW88UkbnOg0Qen".parse()?;
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

    let (not_bus, _ooo_escrow) = default_escrow_bus(db.clone(), escrow_db, EscrowConfig::default());

    let event_processor = BasicProcessor::new(Arc::clone(&db), Some(not_bus));
    let event_storage = EventStorage::new(Arc::clone(&db));

    // Events and sigs are from keripy `test_delegation` test.
    // (keripy/tests/core/test_delegating.py)

    let delegator_icp = br#"{"v":"KERI10JSON00012b_","t":"icp","d":"EA_SbBUZYwqLVlAAn14d6QUBQCSReJlZ755JqTgmRhXH","i":"EA_SbBUZYwqLVlAAn14d6QUBQCSReJlZ755JqTgmRhXH","s":"0","kt":"1","k":["DKiNnDmdOkcBjcAqL2FFhMZnSlPfNyGrJlCjJmX5b1nU"],"nt":"1","n":["EMP7Lg6BtehOYZt2RwOqXLNfMUiUllejAp8G_5EiANXR"],"bt":"0","b":[],"c":[],"a":[]}-AABAAArkDBeflIAo4kBsKnc754XHJvdLnf04iq-noTFEJkbv2MeIGZtx6lIfJPmRSEmFMUkFW4otRrMeBGQ0-nlhHEE"#;
    let parsed = parse(delegator_icp).unwrap().1;
    let msg = Message::try_from(parsed).unwrap();
    event_processor.process(&msg)?;
    let delegator_prefix = "EA_SbBUZYwqLVlAAn14d6QUBQCSReJlZ755JqTgmRhXH".parse()?;

    // Delegated inception event.
    let dip_raw = br#"{"v":"KERI10JSON00015f_","t":"dip","d":"EHng2fV42DdKb5TLMIs6bbjFkPNmIdQ5mSFn6BTnySJj","i":"EHng2fV42DdKb5TLMIs6bbjFkPNmIdQ5mSFn6BTnySJj","s":"0","kt":"1","k":["DLitcfMnabnLt-PNCaXdVwX45wsG93Wd8eW9QiZrlKYQ"],"nt":"1","n":["EDjXvWdaNJx7pAIr72Va6JhHxc7Pf4ScYJG496ky8lK8"],"bt":"0","b":[],"c":[],"a":[],"di":"EA_SbBUZYwqLVlAAn14d6QUBQCSReJlZ755JqTgmRhXH"}-AABAABv6Q3s-1Tif-ksrx7ul9OKyOL_ZPHHp6lB9He4n6kswjm9VvHXzWB3O7RS2OQNWhx8bd3ycg9bWRPRrcKADoYC-GAB0AAAAAAAAAAAAAAAAAAAAAABEJtQndkvwnMpVGE5oVVbLWSCm-jLviGw1AOOkzBvNwsS"#;
    let parsed = parse(dip_raw).unwrap().1;
    let deserialized_dip = Message::try_from(parsed).unwrap();

    let child_prefix = "EHng2fV42DdKb5TLMIs6bbjFkPNmIdQ5mSFn6BTnySJj".parse()?;

    // Delegators's ixn event with delegating event seal.
    let delegator_ixn = br#"{"v":"KERI10JSON00013a_","t":"ixn","d":"EJtQndkvwnMpVGE5oVVbLWSCm-jLviGw1AOOkzBvNwsS","i":"EA_SbBUZYwqLVlAAn14d6QUBQCSReJlZ755JqTgmRhXH","s":"1","p":"EA_SbBUZYwqLVlAAn14d6QUBQCSReJlZ755JqTgmRhXH","a":[{"i":"EHng2fV42DdKb5TLMIs6bbjFkPNmIdQ5mSFn6BTnySJj","s":"0","d":"EHng2fV42DdKb5TLMIs6bbjFkPNmIdQ5mSFn6BTnySJj"}]}-AABAADFmoctrQkBbm47vuk7ejMbQ1y5vKD0Nfo8cqzbETZAlEPdbgVRSFta1-Bpv0y1RiDrCxa_0IOp906gYqDPXIwG"#;
    let parsed = parse(delegator_ixn).unwrap().1;
    let deserialized_ixn = Message::try_from(parsed).unwrap();
    event_processor.process(&deserialized_ixn)?;

    // Helper function for serializing message (without attachments)
    let raw_parsed = |ev: Message| -> Result<Vec<_>, Error> {
        if let Message::Notice(Notice::Event(ev)) = ev {
            Ok(ev.event_message.encode()?)
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
        ixn_from_db.signed_event_message.event_message.encode()?,
        raw_parsed(deserialized_ixn)?
    );

    // Process delegated inception event.
    event_processor.process(&deserialized_dip)?;

    // Check if processed dip event is in db.
    let dip_from_db = event_storage.get_event_at_sn(&child_prefix, 0)?.unwrap();

    assert_eq!(
        dip_from_db.signed_event_message.event_message.encode()?,
        raw_parsed(deserialized_dip.clone())?
    );

    // Delegator's interaction event with delegated event seal.
    let delegator_ixn = br#"{"v":"KERI10JSON00013a_","t":"ixn","d":"EJaPTWDiWvay8voiJkbxkvoabuUf_1a22yk9tVdRiMVs","i":"EA_SbBUZYwqLVlAAn14d6QUBQCSReJlZ755JqTgmRhXH","s":"2","p":"EJtQndkvwnMpVGE5oVVbLWSCm-jLviGw1AOOkzBvNwsS","a":[{"i":"EHng2fV42DdKb5TLMIs6bbjFkPNmIdQ5mSFn6BTnySJj","s":"1","d":"EM5fj7YtOQYH3iLyWJr6HZVVxrY5t46LRL2vkNpdnPi0"}]}-AABAAC8htl4epY7F5QBjro00VdfisxZMZWRXfe6xX_nVfS5gOsv8HOkzUKYMsvAVG4TJg7n1u44IyfsiKrB2R_UeUIK"#;
    let parsed = parse(delegator_ixn).unwrap().1;
    let deserialized_ixn_drt = Message::try_from(parsed).unwrap();

    event_processor.process(&deserialized_ixn_drt)?;

    // Check if processed event is in db.
    let ixn_from_db = event_storage
        .get_event_at_sn(&delegator_prefix, 2)?
        .unwrap();
    assert_eq!(
        ixn_from_db.signed_event_message.event_message.encode()?,
        raw_parsed(deserialized_ixn_drt)?
    );

    // Delegated rotation event.
    let drt_raw = br#"{"v":"KERI10JSON000160_","t":"drt","d":"EM5fj7YtOQYH3iLyWJr6HZVVxrY5t46LRL2vkNpdnPi0","i":"EHng2fV42DdKb5TLMIs6bbjFkPNmIdQ5mSFn6BTnySJj","s":"1","p":"EHng2fV42DdKb5TLMIs6bbjFkPNmIdQ5mSFn6BTnySJj","kt":"1","k":["DE3-kGVqHrdeeKPcL83jLjYS0Ea_CWgFHogusIwf-P9P"],"nt":"1","n":["EMj2mWvNvn6w9BbGUADX1AU3vn7idcUffZIaCvAsibru"],"bt":"0","br":[],"ba":[],"a":[]}-AABAAB_x-9_FTWr-OW_xXBN5pUkFNqLpAqTTQC02sPysnP0WmBFHb8NWvog9F-o279AfpPcLMxktypg1Fz7EQFYCuwC-GAB0AAAAAAAAAAAAAAAAAAAAAACEJaPTWDiWvay8voiJkbxkvoabuUf_1a22yk9tVdRiMVs"#;
    let parsed = parse(drt_raw).unwrap().1;
    let deserialized_drt = Message::try_from(parsed).unwrap();

    // Process drt event.
    event_processor.process(&deserialized_drt)?;

    // Check if processed drt event is in db.
    let drt_from_db = event_storage.get_event_at_sn(&child_prefix, 1)?.unwrap();
    assert_eq!(
        drt_from_db.signed_event_message.event_message.encode()?,
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

    let (not_bus, _ooo_escrow) = default_escrow_bus(db.clone(), escrow_db, EscrowConfig::default());

    let event_processor = BasicProcessor::new(Arc::clone(&db), Some(not_bus));
    let event_storage = EventStorage::new(Arc::clone(&db));

    let kerl_str = br#"{"v":"KERI10JSON000159_","t":"icp","d":"EFb-WY7Ie1WPEgsioZz1CyzwnuCg-C9k2QCNpcUfM5Jf","i":"EFb-WY7Ie1WPEgsioZz1CyzwnuCg-C9k2QCNpcUfM5Jf","s":"0","kt":"1","k":["DIwDbi2Sr1kLZFpsX0Od6Y8ariGVLLjZXxBC5bXEI85e"],"nt":"1","n":["ELhmgZ5JFc-ACs9TJxHMxtcKzQxKXLhlAmUT_sKf1-l7"],"bt":"0","b":["DM73ulUG2_DJyA27DfxBXT5SJ5U3A3c2oeG8Z4bUOgyL"],"c":[],"a":[]}-AABAAAPGpCUdR6EfVWROUjpuTsxg5BIcMnfi7PDciv8VuY9NqZ0ioRoaHxMZue_5ALys86sX4aQzKqm_bID3ZBwlMUP{"v":"KERI10JSON000160_","t":"rot","d":"EBHj01Xvz4yfCnScRh3QgeoE7ntSaVcQwRRQkBTHrHX5","i":"EFb-WY7Ie1WPEgsioZz1CyzwnuCg-C9k2QCNpcUfM5Jf","s":"1","p":"EFb-WY7Ie1WPEgsioZz1CyzwnuCg-C9k2QCNpcUfM5Jf","kt":"1","k":["DGbzWMG2eMghiXRfbbU_JfCB06R1WPE86nYD1XNFRpsL"],"nt":"1","n":["EJypM7yvZBRF-CXqJcCg5j7syRngnwy6TLdq8pSMP9ct"],"bt":"0","br":[],"ba":[],"a":[]}-AABAADbXBjlIg0SgXHzK7YMp1SasIDrRZ2zBG8Ulqee3GtsOBPXG-LFLpmNSa-5EARl3Jq6hn1wZmtagVX3u-U0qN8C{"v":"KERI10JSON000160_","t":"rot","d":"EJUn-ix3QWTa5dyCYaMnyUMLMrkHNXmJPlM6sPpZm8eo","i":"EFb-WY7Ie1WPEgsioZz1CyzwnuCg-C9k2QCNpcUfM5Jf","s":"2","p":"EBHj01Xvz4yfCnScRh3QgeoE7ntSaVcQwRRQkBTHrHX5","kt":"1","k":["DNMcalsTFQRW_gr-0uOo-0GYMSMqrDh-RBmQ9k_tfg5x"],"nt":"1","n":["EAk5C3kZzIWylApdvVdTPRmnGxw8AnhluGBtNVZ-MQlj"],"bt":"0","br":[],"ba":[],"a":[]}-AABAADb7X_2Am8I3G9U8_rMiEpjLVW1AqCJpE2Xn1_dy3grzF6BiGS6hkXlkdBE4tKg3panQkAGgGmWOFMa0wIe8cUN{"v":"KERI10JSON000160_","t":"rot","d":"EDYkjQ0T1CDBpqkSmZiuUEBgIhlwq4CNUXw9Z6pRWrRQ","i":"EFb-WY7Ie1WPEgsioZz1CyzwnuCg-C9k2QCNpcUfM5Jf","s":"3","p":"EJUn-ix3QWTa5dyCYaMnyUMLMrkHNXmJPlM6sPpZm8eo","kt":"1","k":["DGKuTfTIkfsaDGbI_c16ZQ1e_CyC2VCAi5sAgR4Kd-De"],"nt":"1","n":["EDFasM0kFMfgVRV2maR2xEnCT28yr9Cwbjb8AWudLfTB"],"bt":"0","br":[],"ba":[],"a":[]}-AABAAARXXCBpfCrmQ7WmD5WQYjgq--6vYULSMW6RRhXT-lWCe6pDtiP6VqGVO7CQHOF45BN1VfpUIZBjoQMOJxqXREE{"v":"KERI10JSON000160_","t":"rot","d":"EE7l2mmUQVgicVhBbfwHkmzVxeAzYhxDAe2vlZPjJ2Yg","i":"EFb-WY7Ie1WPEgsioZz1CyzwnuCg-C9k2QCNpcUfM5Jf","s":"4","p":"EDYkjQ0T1CDBpqkSmZiuUEBgIhlwq4CNUXw9Z6pRWrRQ","kt":"1","k":["DB-2T6cfJtJp6ZKcTaA31qTZRp8Jh9Xs0RpThQWh6-0X"],"nt":"1","n":["EC2AwY44hG7GbKKjpu39yg9sq_2h80184XPO-v7BBJw8"],"bt":"0","br":[],"ba":[],"a":[]}-AABAADm6yCLOiht10BodxeL8U4gCmZQMFZ6IjYgPaX8xBvNZFb-4Kdk3STrIOm7M2XWQ2V7xyu--VrhI4TExqqjvFcB"#;
    // Process kerl
    parse_many(kerl_str)
        .unwrap()
        .1
        .into_iter()
        .for_each(|event| {
            event_processor
                .process(&Message::try_from(event.clone()).unwrap())
                .unwrap();
        });

    let event_seal = EventSeal {
        prefix: "EFb-WY7Ie1WPEgsioZz1CyzwnuCg-C9k2QCNpcUfM5Jf".parse()?,
        sn: 2,
        event_digest: "EJUn-ix3QWTa5dyCYaMnyUMLMrkHNXmJPlM6sPpZm8eo".parse()?,
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
pub fn test_partial_rotation_simple_threshold() -> Result<(), Error> {
    use tempfile::Builder;
    let db_root = Builder::new().prefix("test-db").tempdir().unwrap();
    let path = db_root.path();
    std::fs::create_dir_all(path).unwrap();
    let db = Arc::new(SledEventDatabase::new(path).unwrap());

    let escrow_root = Builder::new().prefix("test-db-escrow").tempdir().unwrap();
    let escrow_db = Arc::new(EscrowDb::new(escrow_root.path()).unwrap());

    let (not_bus, (_, ps_escrow, _, _)) = default_escrow_bus(db.clone(), escrow_db, EscrowConfig::default());

    let processor = BasicProcessor::new(db.clone(), Some(not_bus));
    // setup keypairs
    let signers = setup_signers();

    let keys = vec![BasicPrefix::Ed25519(signers[0].public_key())];
    let next_pks = signers[1..6]
        .iter()
        .map(|signer| BasicPrefix::Ed25519(signer.public_key()))
        .collect::<Vec<_>>();
    // build inception event
    let icp = EventMsgBuilder::new(EventTypeTag::Icp)
        .with_keys(keys)
        .with_threshold(&SignatureThreshold::Simple(1))
        .with_next_keys(next_pks)
        .with_next_threshold(&SignatureThreshold::Simple(2))
        .build()
        .unwrap();
    // {"v":"KERI10JSON0001e7_","t":"icp","d":"EKkedrfoZz54Xsb_lGGdKTkYqNMf6TMrX1x57M1j0yi3","i":"EKkedrfoZz54Xsb_lGGdKTkYqNMf6TMrX1x57M1j0yi3","s":"0","kt":"1","k":["DErocgXD2RGSyvn3MObcx59jeOsEQhv2TqHirVkzrp0Q"],"nt":"2","n":["EIQsSW4KMrLzY1HQI9H_XxY6MyzhaFFXhG6fdBb5Wxta","EHuvLs1hmwxo4ImDoCpaAermYVQhiPsPDNaZsz4bcgko","EDJk5EEpC4-tQ7YDwBiKbpaZahh1QCyQOnZRF7p2i8k8","EAXfDjKvUFRj-IEB_o4y-Y_qeJAjYfZtOMD9e7vHNFss","EN8l6yJC2PxribTN0xfri6bLz34Qvj-x3cNwcV3DvT2m"],"bt":"0","b":[],"c":[],"a":[]}

    let id_prefix = icp.data.get_prefix();
    let icp_digest = icp.get_digest();
    assert_eq!(
        id_prefix,
        IdentifierPrefix::SelfAddressing(icp_digest.clone())
    );
    assert_eq!(
        id_prefix.to_str(),
        "EKkedrfoZz54Xsb_lGGdKTkYqNMf6TMrX1x57M1j0yi3"
    );
    // sign inception event
    let signature = signers[0].sign(icp.encode().unwrap())?;
    let signed_icp = icp.sign(
        vec![AttachedSignaturePrefix::new_both_same(
            SelfSigningPrefix::Ed25519Sha512(signature),
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
        .map(|sig| BasicPrefix::Ed25519(sig.public_key()))
        .collect::<Vec<_>>();
    let next_public_keys = signers[6..11]
        .iter()
        .map(|sig| BasicPrefix::Ed25519(sig.public_key()))
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

    let rot_digest = rotation.get_digest();

    let signatures = current_signers
        .iter()
        .enumerate()
        .map(|(index, sig)| {
            let signature = sig.sign(rotation.encode().unwrap()).unwrap();
            AttachedSignaturePrefix::new_both_same(
                SelfSigningPrefix::Ed25519Sha512(signature),
                index as u16,
            )
        })
        .collect::<Vec<_>>();

    let signed_rotation = rotation.sign(signatures, None, None);

    processor.process_notice(&Notice::Event(signed_rotation))?;
    let state = EventStorage::new(db.clone()).get_state(&id_prefix)?;
    assert_eq!(state.unwrap().sn, 1);

    let current_signers = [&signers[6], &signers[7], &signers[8]];
    let next_public_keys = signers[11..16]
        .iter()
        .map(|sig| BasicPrefix::Ed25519(sig.public_key()))
        .collect::<Vec<_>>();
    let current_public_keys = current_signers
        .iter()
        .map(|sig| BasicPrefix::Ed25519(sig.public_key()))
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
            let signature = sig.sign(rotation.encode().unwrap()).unwrap();
            AttachedSignaturePrefix::new_both_same(
                SelfSigningPrefix::Ed25519Sha512(signature),
                index as u16,
            )
        })
        .collect::<Vec<_>>();

    let signed_rotation = rotation.sign(signatures, None, None);
    processor.process_notice(&Notice::Event(signed_rotation.clone()))?;
    // rotation should be stored in partially signed events escrow.
    assert_eq!(
        ps_escrow
            .escrowed_partially_signed
            .get_all()
            .and_then(|mut x| x.next()),
        Some(signed_rotation)
    );

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

        let (not_bus, _ooo_escrow) =
            default_escrow_bus(db.clone(), escrow_db, EscrowConfig::default());
        (
            BasicProcessor::new(db.clone(), Some(not_bus)),
            EventStorage::new(db.clone()),
        )
    };
    // setup keypairs
    let signers = setup_signers();

    let keys = vec![BasicPrefix::Ed25519(signers[0].public_key())];
    let next_pks = signers[1..6]
        .iter()
        .map(|signer| BasicPrefix::Ed25519(signer.public_key()))
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

    let id_prefix = icp.data.get_prefix();
    let icp_digest = icp.get_digest();
    assert_eq!(
        id_prefix,
        IdentifierPrefix::SelfAddressing(icp_digest.clone())
    );
    assert_eq!(
        id_prefix.to_str(),
        "EM2y0cPBcua33FMaji79hQ2NVq7mzIIEX8Zlw0Ch5OQQ"
    );
    // sign inception event
    let signature = signers[0].sign(icp.encode().unwrap())?;
    let signed_icp = icp.sign(
        vec![AttachedSignaturePrefix::new_both_same(
            SelfSigningPrefix::Ed25519Sha512(signature),
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
        .map(|sig| BasicPrefix::Ed25519(sig.public_key()))
        .collect::<Vec<_>>();
    let next_public_keys = signers[11..16]
        .iter()
        .map(|sig| BasicPrefix::Ed25519(sig.public_key()))
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

    let rot_digest = rotation.get_digest();

    let signatures = current_signers
        .iter()
        .enumerate()
        .map(|(index, sig)| {
            let signature = sig.sign(rotation.encode().unwrap()).unwrap();
            AttachedSignaturePrefix::new_both_same(
                SelfSigningPrefix::Ed25519Sha512(signature),
                index as u16,
            )
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

    let current_signers = [&signers[13], &signers[14], &signers[15]];
    let next_public_keys = vec![];
    let current_public_keys = current_signers
        .iter()
        .map(|sig| BasicPrefix::Ed25519(sig.public_key()))
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

    // Not enough signatures to satisfy previous threshold.
    let signatures = current_signers[1..3]
        .iter()
        .enumerate()
        .map(|(index, sig)| {
            let signature = sig.sign(rotation.encode().unwrap()).unwrap();
            AttachedSignaturePrefix::new_both_same(
                SelfSigningPrefix::Ed25519Sha512(signature),
                (index + 1) as u16,
            )
        })
        .collect::<Vec<_>>();

    println!("len: {}", signatures.len());
    let signed_rotation = rotation.sign(signatures, None, None);
    processor.process_notice(&Notice::Event(signed_rotation))?;

    // State shouldn't be updated.
    let state = storage.get_state(&id_prefix)?.unwrap();
    assert_eq!(state.sn, 1);

    Ok(())
}
